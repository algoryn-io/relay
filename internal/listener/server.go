package listener

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"algoryn.io/relay/internal/admin"
	"algoryn.io/relay/internal/config"
	"algoryn.io/relay/internal/httpx"
	"algoryn.io/relay/internal/middleware"
	"algoryn.io/relay/internal/observability"
	"algoryn.io/relay/internal/proxy"
	"algoryn.io/relay/internal/router"
)

const (
	// defaultReadHeaderTimeout bounds request-header reads to mitigate Slowloris
	// when no explicit value is configured.
	defaultReadHeaderTimeout = 10 * time.Second
	// defaultMaxHeaderBytes caps request header size (matches Go's default).
	defaultMaxHeaderBytes = 1 << 20
	// defaultStateDrainTimeout bounds how long a retired configuration remains
	// alive waiting for requests that acquired it before an atomic reload.
	defaultStateDrainTimeout = 30 * time.Second
)

// serverState holds all hot-reloadable request-handling state.
// Requests acquire a lease before touching it. Retirement rejects new leases and
// closes owned resources after existing leases drain (or the bounded timeout).
type serverState struct {
	proxy               *proxy.Proxy
	router              *router.Router
	metrics             *observability.Metrics
	metricsH            http.Handler
	prometheusH         http.Handler
	prometheus          *observability.PrometheusCollector
	prometheusPath      string
	metricsAllowedNets  []*net.IPNet // extra peers (beyond loopback) allowed to scrape metrics
	routes              map[string]*compiledRoute
	trustedNets         []*net.IPNet
	fabricDispatch      *observability.EventDispatcher
	relayServiceName    string
	adminH              http.Handler
	healthAccess        *admin.AccessControl
	readinessPolicy     config.ReadinessPolicyConfig
	stripHeaders        []string // extra inbound headers to remove at the edge
	emitForwardedHeader bool
	owner               *resourceOwner

	leaseMu     sync.Mutex
	leases      int
	retired     bool
	drained     chan struct{}
	drainedOnce sync.Once
	retireOnce  sync.Once
	closeOnce   sync.Once
	done        chan struct{}
	onClose     func()
}

type resourceOwner struct {
	once    sync.Once
	closers []io.Closer
}

func (o *resourceOwner) add(c io.Closer) {
	if c != nil {
		o.closers = append(o.closers, c)
	}
}

func (o *resourceOwner) close() {
	if o == nil {
		return
	}
	o.once.Do(func() {
		for i := len(o.closers) - 1; i >= 0; i-- {
			_ = o.closers[i].Close()
		}
		o.closers = nil
	})
}

type closerFunc func() error

func (f closerFunc) Close() error { return f() }

func (st *serverState) acquire() bool {
	st.leaseMu.Lock()
	defer st.leaseMu.Unlock()
	if st.retired {
		return false
	}
	st.leases++
	return true
}

func (st *serverState) release() {
	st.leaseMu.Lock()
	if st.leases > 0 {
		st.leases--
	}
	if st.retired && st.leases == 0 {
		st.drainedOnce.Do(func() { close(st.drained) })
	}
	st.leaseMu.Unlock()
}

func (st *serverState) retire(timeout time.Duration) {
	if st == nil {
		return
	}
	st.retireOnce.Do(func() {
		st.leaseMu.Lock()
		st.retired = true
		if st.leases == 0 {
			st.drainedOnce.Do(func() { close(st.drained) })
		}
		st.leaseMu.Unlock()

		go func() {
			if timeout <= 0 {
				<-st.drained
			} else {
				timer := time.NewTimer(timeout)
				defer timer.Stop()
				select {
				case <-st.drained:
				case <-timer.C:
				}
			}
			st.close()
		}()
	})
}

func (st *serverState) close() {
	if st == nil {
		return
	}
	st.closeOnce.Do(func() {
		st.owner.close()
		if st.onClose != nil {
			st.onClose()
		}
		close(st.done)
	})
}

type Server struct {
	httpServer   *http.Server
	httpsServer  *http.Server // nil when HTTPS is not configured
	tlsHandle    *TLSConfigHandle
	tlsResource  io.Closer
	tlsResources []io.Closer
	httpPort     int
	httpsPort    int
	tlsMode      string
	logger       *slog.Logger
	tracing      *observability.TracingHandle
	metrics      *observability.Metrics
	prometheus   *observability.PrometheusCollector
	operational  *observability.OperationalEvents
	state        atomic.Pointer[serverState]
	lifecycleMu  sync.Mutex
	shuttingDown bool
	shutdownDone chan struct{}
	states       map[*serverState]struct{}
	drainTimeout time.Duration

	inFlight            atomic.Int64 // currently in-flight proxied requests
	maxInFlight         atomic.Int64 // global cap; 0 = unlimited (resizable on reload)
	maxRequestBodyBytes atomic.Int64 // global body cap; route limits can override it
	connectionLimiter   *connectionLimiter
}

type compiledRoute struct {
	route   *config.RouteRuntime
	handler http.Handler
}

// New builds the server(s). When listener.https.port is set, a TLS server is
// created alongside the HTTP server. If only HTTPS is configured, the HTTP
// server redirects all requests to the HTTPS port.
func New(
	cfg *config.Config,
	rt *config.RuntimeConfig,
	logger *slog.Logger,
	tracing ...*observability.TracingHandle,
) (*Server, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config must not be nil")
	}
	if rt == nil {
		return nil, fmt.Errorf("runtime config must not be nil")
	}
	if cfg.Listener.HTTP.Port <= 0 && cfg.Listener.HTTPS.Port <= 0 {
		return nil, fmt.Errorf("listener: at least one of http.port or https.port must be configured")
	}
	if logger == nil {
		logger = slog.Default()
	}

	metrics := observability.NewMetrics(100)
	prometheus := observability.NewPrometheusCollector()
	operational := observability.NewOperationalEvents(logger, prometheus)
	var tracingHandle *observability.TracingHandle
	if len(tracing) > 0 {
		tracingHandle = tracing[0]
	}
	st, err := buildStateShared(cfg, rt, logger, tracingHandle, metrics, prometheus, operational)
	if err != nil {
		return nil, err
	}
	keepState := false
	defer func() {
		if !keepState {
			st.close()
		}
	}()

	s := &Server{
		logger:            logger,
		tracing:           tracingHandle,
		metrics:           metrics,
		prometheus:        prometheus,
		operational:       operational,
		httpPort:          cfg.Listener.HTTP.Port,
		httpsPort:         cfg.Listener.HTTPS.Port,
		tlsMode:           normalizedTLSMode(cfg.Listener.HTTPS.TLS.Mode),
		connectionLimiter: newConnectionLimiter(cfg.Listener.MaxConnectionsPerIP),
		shutdownDone:      make(chan struct{}),
		states:            make(map[*serverState]struct{}),
		drainTimeout:      defaultStateDrainTimeout,
	}
	st.onClose = func() { s.removeState(st) }
	s.states[st] = struct{}{}
	s.state.Store(st)
	s.operational.SetFabric(st.fabricDispatch, st.relayServiceName)
	s.operational.ConfigureRateLimitRedisSources(rateLimitRedisSources(rt))
	s.connectionLimiter.setMetrics(st.prometheus)
	s.maxInFlight.Store(int64(cfg.Listener.MaxConcurrentRequests))
	s.maxRequestBodyBytes.Store(cfg.Listener.MaxRequestBodyBytes)

	timeouts := cfg.Listener.Timeouts
	httpsPort := cfg.Listener.HTTPS.Port

	readHeaderTimeout := timeouts.ReadHeader
	if readHeaderTimeout <= 0 {
		readHeaderTimeout = defaultReadHeaderTimeout
	}

	// HTTP server: either serves requests directly, or redirects to HTTPS.
	httpHandler := http.Handler(s)
	if httpsPort > 0 && cfg.Listener.HTTP.Port > 0 {
		httpHandler = httpsRedirectHandler(cfg.Listener.HTTP, httpsPort)
	}

	if cfg.Listener.HTTP.Port > 0 {
		s.httpServer = &http.Server{
			Addr:              fmt.Sprintf(":%d", cfg.Listener.HTTP.Port),
			Handler:           httpHandler,
			ReadTimeout:       timeouts.Read,
			ReadHeaderTimeout: readHeaderTimeout,
			WriteTimeout:      timeouts.Write,
			IdleTimeout:       timeouts.Idle,
			MaxHeaderBytes:    defaultMaxHeaderBytes,
			ConnState:         s.connectionLimiter.connState,
			// Accept cleartext HTTP/2 (h2c) alongside HTTP/1.1 so gRPC and other
			// HTTP/2 clients can connect without TLS. Uses stdlib support for
			// unencrypted HTTP/2 (Go 1.24+); transparent to HTTP/1.1 clients.
			Protocols: h2cServerProtocols(),
		}
	}

	if httpsPort > 0 {
		prepared, err := prepareTLSBundle(cfg.Listener.HTTPS.TLS)
		if err != nil {
			return nil, fmt.Errorf("tls config: %w", err)
		}
		handle := newTLSConfigHandle(prepared.config)
		tlsCfg := prepared.config.Clone()
		tlsCfg.GetConfigForClient = handle.GetConfigForClient
		s.tlsHandle = handle
		s.tlsResource = prepared.closer
		if prepared.closer != nil {
			s.tlsResources = append(s.tlsResources, prepared.closer)
		}
		s.httpsServer = &http.Server{
			Addr:              fmt.Sprintf(":%d", httpsPort),
			Handler:           s,
			TLSConfig:         tlsCfg,
			ReadTimeout:       timeouts.Read,
			ReadHeaderTimeout: readHeaderTimeout,
			WriteTimeout:      timeouts.Write,
			IdleTimeout:       timeouts.Idle,
			MaxHeaderBytes:    defaultMaxHeaderBytes,
			ConnState:         s.connectionLimiter.connState,
		}
		// When only HTTPS is configured, the HTTP server is nil; Start() still
		// works because it only starts the servers that are non-nil.
	}

	keepState = true
	return s, nil
}

// Reload applies a new config without restarting the process. The TCP listener
// stays open; only the request-handling state (routes, backends, middleware,
// metrics) is replaced. In-flight requests on the old state complete normally.
// Returns an error if the new state cannot be built; the server keeps running
// with the previous config in that case.
func (s *Server) Reload(cfg *config.Config, rt *config.RuntimeConfig) error {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if s.shuttingDown {
		return fmt.Errorf("server is shutting down")
	}
	if cfg == nil {
		return fmt.Errorf("reload config must not be nil")
	}
	if rt == nil {
		return fmt.Errorf("reload runtime config must not be nil")
	}
	if cfg.Listener.HTTP.Port != s.httpPort || cfg.Listener.HTTPS.Port != s.httpsPort {
		return fmt.Errorf(
			"hot reload cannot change listener ports (http %d->%d, https %d->%d); restart Relay",
			s.httpPort, cfg.Listener.HTTP.Port, s.httpsPort, cfg.Listener.HTTPS.Port,
		)
	}
	if mode := normalizedTLSMode(cfg.Listener.HTTPS.TLS.Mode); mode != s.tlsMode {
		return fmt.Errorf("hot reload cannot change TLS mode from %q to %q; restart Relay", s.tlsMode, mode)
	}

	var preparedTLS *tlsPreparation
	if s.tlsHandle != nil {
		var err error
		preparedTLS, err = prepareTLSBundle(cfg.Listener.HTTPS.TLS)
		if err != nil {
			return fmt.Errorf("prepare reloaded TLS config: %w", err)
		}
	}

	newState, err := buildStateShared(cfg, rt, s.logger, s.tracing, s.metrics, s.prometheus, s.operational)
	if err != nil {
		if preparedTLS != nil && preparedTLS.closer != nil {
			_ = preparedTLS.closer.Close()
		}
		return fmt.Errorf("build reloaded state: %w", err)
	}
	newState.onClose = func() { s.removeState(newState) }
	s.states[newState] = struct{}{}

	if preparedTLS != nil {
		oldResource := s.tlsResource
		s.tlsHandle.Store(preparedTLS.config)
		s.tlsResource = preparedTLS.closer
		if preparedTLS.closer != nil {
			s.tlsResources = append(s.tlsResources, preparedTLS.closer)
		}
		if oldResource != nil {
			go func(resource io.Closer, delay time.Duration) {
				timer := time.NewTimer(delay)
				defer timer.Stop()
				<-timer.C
				_ = resource.Close()
			}(oldResource, s.drainTimeout)
		}
	}
	old := s.state.Swap(newState)
	s.operational.SetFabric(newState.fabricDispatch, newState.relayServiceName)
	s.operational.ConfigureRateLimitRedisSources(rateLimitRedisSources(rt))
	old.retire(s.drainTimeout)

	s.connectionLimiter.setLimit(cfg.Listener.MaxConnectionsPerIP)
	s.connectionLimiter.setMetrics(newState.prometheus)
	s.maxInFlight.Store(int64(cfg.Listener.MaxConcurrentRequests))
	s.maxRequestBodyBytes.Store(cfg.Listener.MaxRequestBodyBytes)

	return nil
}

// RecordConfigReload exposes process-lifetime reload telemetry without
// replacing the registry when request-handling state is rebuilt.
func (s *Server) RecordConfigReload(result, stage string) {
	if s != nil {
		s.operational.RecordConfigReload(result, stage)
	}
}

// Start launches all configured servers concurrently and blocks until one of
// them fails. A graceful shutdown via Shutdown is not considered an error.
func (s *Server) Start() error {
	errCh := make(chan error, 2)

	if s.httpServer != nil {
		go func() {
			err := s.httpServer.ListenAndServe()
			if errors.Is(err, http.ErrServerClosed) {
				err = nil
			}
			errCh <- err
		}()
	}

	if s.httpsServer != nil {
		go func() {
			// TLSConfig is already set; passing empty strings lets Go use it.
			err := s.httpsServer.ListenAndServeTLS("", "")
			if errors.Is(err, http.ErrServerClosed) {
				err = nil
			}
			errCh <- err
		}()
	}

	// Wait for either server to exit.
	count := 0
	if s.httpServer != nil {
		count++
	}
	if s.httpsServer != nil {
		count++
	}
	for range count {
		if err := <-errCh; err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.lifecycleMu.Lock()
	if s.shuttingDown {
		done := s.shutdownDone
		s.lifecycleMu.Unlock()
		select {
		case <-done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	s.shuttingDown = true
	s.lifecycleMu.Unlock()

	// Drain the HTTP servers first so in-flight requests finish while the
	// proxy/dispatcher are still alive; only then tear down the state.
	var firstErr error
	for _, srv := range []*http.Server{s.httpServer, s.httpsServer} {
		if srv == nil {
			continue
		}
		if err := srv.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	s.lifecycleMu.Lock()
	states := make([]*serverState, 0, len(s.states))
	for st := range s.states {
		states = append(states, st)
	}
	s.lifecycleMu.Unlock()

	for _, st := range states {
		st.retire(s.drainTimeout)
	}
	for _, st := range states {
		select {
		case <-st.done:
		case <-ctx.Done():
			// The caller's shutdown bound takes precedence over the normal reload
			// drain bound. Closing is idempotent and releases every owned resource.
			for _, pending := range states {
				pending.close()
			}
			if firstErr == nil {
				firstErr = ctx.Err()
			}
			goto finished
		}
	}

finished:
	s.lifecycleMu.Lock()
	tlsResources := append([]io.Closer(nil), s.tlsResources...)
	s.tlsResources = nil
	s.tlsResource = nil
	s.lifecycleMu.Unlock()
	for _, resource := range tlsResources {
		_ = resource.Close()
	}
	close(s.shutdownDone)
	return firstErr
}

func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	st := s.acquireState()
	if st == nil {
		httpx.WriteError(w, http.StatusServiceUnavailable, "shutting_down")
		return
	}
	defer st.release()

	// Resolve the client IP (honoring trusted proxies) into the request context
	// first, then strip spoofable inbound headers. Resolution happens before the
	// strip so removing X-Forwarded-* here never affects client-IP resolution.
	req = httpx.WithForwarding(req, st.trustedNets, st.emitForwardedHeader)
	stripUntrustedHeaders(req, st.trustedNets, st.stripHeaders)

	switch {
	case req.URL.Path == "/_relay/metrics":
		// Gate on the real TCP peer, not the (spoofable) forwarded client IP.
		if !metricsPeerAllowed(req, st.metricsAllowedNets) {
			httpx.WriteError(w, http.StatusForbidden, "forbidden")
			return
		}
		st.metricsH.ServeHTTP(w, req)
		return
	case req.URL.Path == "/_relay/health":
		if !allowHealthRequest(w, req, st.healthAccess) {
			return
		}
		// Liveness: the process is up and serving.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
		return
	case req.URL.Path == "/_relay/ready":
		if !allowHealthRequest(w, req, st.healthAccess) {
			return
		}
		writeReadiness(w, st.proxy, st.readinessPolicy)
		return
	case req.URL.Path == st.prometheusPath:
		// Same exposure as the JSON metrics endpoint: loopback plus any configured
		// scrape CIDRs, checked against the real TCP peer.
		if !metricsPeerAllowed(req, st.metricsAllowedNets) {
			httpx.WriteError(w, http.StatusForbidden, "forbidden")
			return
		}
		st.prometheusH.ServeHTTP(w, req)
		return
	case strings.HasPrefix(req.URL.Path, "/_relay/admin"):
		st.adminH.ServeHTTP(w, req)
		return
	}

	// Global backpressure: cap in-flight proxied requests. Internal endpoints
	// above are exempt so health/readiness/metrics stay reachable under overload.
	if max := s.maxInFlight.Load(); max > 0 {
		n := s.inFlight.Add(1)
		defer s.inFlight.Add(-1)
		if n > max {
			httpx.WriteError(w, http.StatusServiceUnavailable, "overloaded")
			return
		}
	}

	route, err := st.router.Match(req)
	switch {
	case err == nil:
		compiled, ok := st.routes[route.Name]
		if !ok || compiled == nil || compiled.handler == nil {
			s.logger.Error("compiled route not found", "route", route.Name)
			httpx.WriteError(w, http.StatusInternalServerError, "internal_error")
			return
		}
		limit := s.maxRequestBodyBytes.Load()
		if compiled.route.MaxBodyBytes > 0 {
			limit = compiled.route.MaxBodyBytes
		}
		if limit > 0 && req.Body != nil && req.Body != http.NoBody {
			if req.ContentLength > limit {
				httpx.WriteError(w, http.StatusRequestEntityTooLarge, "request_body_too_large")
				return
			}
			req.Body = http.MaxBytesReader(w, req.Body, limit)
		}
		compiled.handler.ServeHTTP(w, req)
	case errors.Is(err, router.ErrMethodNotAllowed):
		httpx.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed")
	case errors.Is(err, router.ErrNotFound):
		httpx.WriteError(w, http.StatusNotFound, "not_found")
	default:
		s.logger.Error("request match failed", "error", err)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error")
	}
}

func (s *Server) acquireState() *serverState {
	for {
		st := s.state.Load()
		if st == nil {
			return nil
		}
		if st.acquire() {
			return st
		}
		if s.state.Load() == st {
			return nil
		}
	}
}

func (s *Server) removeState(st *serverState) {
	s.lifecycleMu.Lock()
	delete(s.states, st)
	s.lifecycleMu.Unlock()
}

func buildState(cfg *config.Config, rt *config.RuntimeConfig, logger *slog.Logger) (st *serverState, err error) {
	return buildStateShared(
		cfg,
		rt,
		logger,
		nil,
		observability.NewMetrics(100),
		observability.NewPrometheusCollector(),
		nil,
	)
}

func buildStateShared(
	cfg *config.Config,
	rt *config.RuntimeConfig,
	logger *slog.Logger,
	tracing *observability.TracingHandle,
	metrics *observability.Metrics,
	promCollector *observability.PrometheusCollector,
	operational *observability.OperationalEvents,
) (st *serverState, err error) {
	owner := &resourceOwner{}
	defer func() {
		if err != nil {
			owner.close()
		}
	}()

	rtRouter, err := router.New(rt)
	if err != nil {
		return nil, err
	}
	rtProxy, err := proxy.New(rt, logger)
	if err != nil {
		return nil, err
	}
	owner.add(closerFunc(func() error {
		rtProxy.Close()
		return nil
	}))
	rtProxy.SetWebSocketIdleTimeout(cfg.Listener.Timeouts.WebSocketIdle)

	if operational == nil {
		operational = observability.NewOperationalEvents(logger, promCollector)
	}
	mwRegistry, mwClosers, err := middleware.BuildRegistry(rt.Middleware, logger, operational)
	if err != nil {
		return nil, err
	}
	for _, closer := range mwClosers {
		owner.add(closer)
	}

	rtProxy.SetHealthNotifier(promCollector)
	rtProxy.SetMetrics(promCollector)
	for backendName, backend := range rt.Backends {
		hasHealthCheck := backend.HealthCheck.Path != "" && backend.HealthCheck.Interval > 0
		for _, inst := range backend.Instances {
			promCollector.NotifyBackendHealth(backendName, inst.URL, !hasHealthCheck)
		}
	}

	relaySvc := strings.TrimSpace(cfg.Observability.Fabric.ServiceName)
	var fabricDispatch *observability.EventDispatcher
	if cfg.Observability.Fabric.Enabled {
		queueSize := cfg.Observability.Fabric.QueueSize
		if queueSize <= 0 {
			queueSize = 1024
		}
		fabricDispatch = observability.NewEventDispatcher(queueSize, logger, nil)
		owner.add(closerFunc(func() error {
			fabricDispatch.Close()
			return nil
		}))
		if relaySvc == "" {
			relaySvc = "relay"
		}
	}

	compiledRoutes := make(map[string]*compiledRoute, len(rt.Routes))
	for routeName, routeRuntime := range rt.Routes {
		route := routeRuntime
		routeRef := &route

		final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if routeRef.Timeout > 0 {
				ctx, cancel := context.WithTimeout(r.Context(), routeRef.Timeout)
				defer cancel()
				r = r.WithContext(ctx)
			}
			if routeRef.StripPrefix != "" {
				stripped := strings.TrimPrefix(r.URL.Path, routeRef.StripPrefix)
				if stripped == "" {
					stripped = "/"
				}
				r2 := r.Clone(r.Context())
				r2.URL.Path = stripped
				if r.URL.RawPath != "" {
					r2.URL.RawPath = strings.TrimPrefix(r.URL.RawPath, routeRef.StripPrefix)
				}
				rtProxy.ServeHTTP(w, r2, routeRef)
				return
			}
			rtProxy.ServeHTTP(w, r, routeRef)
		})

		routeMiddlewares, resolveErr := middleware.Resolve(routeRef.MiddlewareRefs, mwRegistry)
		if resolveErr != nil {
			return nil, fmt.Errorf("resolve middleware for route %q: %w", routeRef.Name, resolveErr)
		}
		routeHandler := middleware.Chain(final, routeMiddlewares...)
		recoveryMW := middleware.Recovery(logger)
		requestIDMW := middleware.RequestID()
		loggingMW := observability.NewLoggingMiddlewareWithConfig(
			logger, routeRef.Name, routeRef.BackendName, cfg.Observability.Logs.Access,
		)
		metricsMW := observability.NewMetricsMiddlewareFabric(metrics, promCollector, fabricDispatch, relaySvc, routeRef.Name)
		tracingMW := observability.NewTracingMiddlewareWithHandle(tracing, routeRef.Name, routeRef.BackendName)

		compiledRoutes[routeName] = &compiledRoute{
			route:   routeRef,
			handler: middleware.Chain(routeHandler, recoveryMW, requestIDMW, tracingMW, loggingMW, metricsMW),
		}
	}

	trustedNets := httpx.ParseTrustedNets(cfg.Listener.TrustedProxies)

	promPath := cfg.Observability.Prometheus.Path
	if promPath == "" {
		promPath = "/_relay/metrics/prometheus"
	}

	adminH := admin.NewWithReadiness(
		rtProxy,
		rt.Routes,
		cfg.Listener.Admin.AllowedCIDRs,
		cfg.Listener.Admin.ResolvedToken,
		cfg.Listener.Health.Readiness,
		logger,
	)

	st = &serverState{
		proxy:              rtProxy,
		router:             rtRouter,
		metrics:            metrics,
		metricsH:           observability.MetricsHandler(metrics),
		prometheusH:        promCollector.Handler(),
		prometheus:         promCollector,
		prometheusPath:     promPath,
		metricsAllowedNets: httpx.ParseTrustedNets(cfg.Observability.Prometheus.AllowedCIDRs),
		routes:             compiledRoutes,
		trustedNets:        trustedNets,
		fabricDispatch:     fabricDispatch,
		relayServiceName:   relaySvc,
		adminH:             adminH,
		healthAccess: admin.NewAccessControl(
			cfg.Listener.Health.Access.AllowedCIDRs,
			cfg.Listener.Health.Access.ResolvedToken,
			true,
		),
		readinessPolicy:     cfg.Listener.Health.Readiness,
		stripHeaders:        cfg.Listener.StripRequestHeaders,
		emitForwardedHeader: cfg.Listener.EmitForwardedHeader,
		owner:               owner,
		drained:             make(chan struct{}),
		done:                make(chan struct{}),
	}

	if fabricDispatch != nil {
		for _, b := range rt.Backends {
			for _, inst := range b.Instances {
				if strings.TrimSpace(inst.URL) == "" {
					continue
				}
				evt := observability.BuildServiceRegisteredFabricEvent(relaySvc, b.Name, inst.URL)
				fabricDispatch.TryEnqueue(observability.FabricDispatchItem{Event: evt})
			}
		}
	}

	return st, nil
}

func rateLimitRedisSources(rt *config.RuntimeConfig) []string {
	if rt == nil {
		return nil
	}
	sources := make([]string, 0)
	for name, definition := range rt.Middleware {
		if definition.Type == "rate_limit" && strings.EqualFold(strings.TrimSpace(definition.Config.RateLimitStore), "redis") {
			sources = append(sources, name)
		}
	}
	return sources
}

// buildTLSConfig creates a stable listener config backed by an atomic handle.
// Reload prepares a complete replacement before publishing it, so certificates,
// client trust, authentication policy and protocol parameters change together.
func buildTLSConfig(cfg config.TLSConfig) (*tls.Config, *TLSConfigHandle, error) {
	prepared, err := prepareTLSBundle(cfg)
	if err != nil {
		return nil, nil, err
	}
	handle := newTLSConfigHandle(prepared.config)
	listenerCfg := prepared.config.Clone()
	listenerCfg.GetConfigForClient = handle.GetConfigForClient
	return listenerCfg, handle, nil
}

func prepareTLSConfig(cfg config.TLSConfig) (*tls.Config, error) {
	prepared, err := prepareTLSBundle(cfg)
	if err != nil {
		return nil, err
	}
	return prepared.config, nil
}

type tlsPreparation struct {
	config *tls.Config
	closer io.Closer
}

func prepareTLSBundle(cfg config.TLSConfig) (*tlsPreparation, error) {
	switch normalizedTLSMode(cfg.Mode) {
	case "manual":
		certificates, err := loadSNICertificates(cfg)
		if err != nil {
			return nil, err
		}
		tlsCfg := &tls.Config{
			GetCertificate: certificates.GetCertificate,
			NextProtos:     []string{"h2", "http/1.1"},
		}
		if err := applyTLSHardening(tlsCfg, cfg); err != nil {
			return nil, err
		}
		return &tlsPreparation{config: tlsCfg}, nil

	case "auto":
		var cache autocert.Cache
		var closer io.Closer
		backend := strings.ToLower(strings.TrimSpace(cfg.ACMECache.Backend))
		if backend == "" && (strings.TrimSpace(cfg.ACMECache.Directory) != "" || strings.TrimSpace(cfg.ACMECacheDir) != "") {
			backend = "filesystem"
		}
		switch backend {
		case "filesystem":
			cacheDir := strings.TrimSpace(cfg.ACMECache.Directory)
			if cacheDir == "" {
				cacheDir = strings.TrimSpace(cfg.ACMECacheDir)
			}
			if cacheDir == "" {
				return nil, fmt.Errorf("acme_cache.directory is required for filesystem ACME cache")
			}
			cache = autocert.DirCache(cacheDir)
		case "redis":
			redisCache, err := newRedisACMECache(cfg)
			if err != nil {
				return nil, err
			}
			cache = redisCache
			closer = redisCache
		default:
			return nil, fmt.Errorf("acme_cache.backend must be filesystem or redis")
		}
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Email:      strings.TrimSpace(cfg.ACMEEmail),
			HostPolicy: autocert.HostWhitelist(cfg.Domains...),
			Cache:      cache,
		}
		tlsCfg := m.TLSConfig()
		if err := applyTLSHardening(tlsCfg, cfg); err != nil {
			if closer != nil {
				_ = closer.Close()
			}
			return nil, err
		}
		return &tlsPreparation{config: tlsCfg, closer: closer}, nil

	default:
		return nil, fmt.Errorf("unknown TLS mode %q", cfg.Mode)
	}
}

func normalizedTLSMode(mode string) string {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		return "manual"
	}
	return mode
}

// hardenedTLS12Ciphers is a conservative TLS 1.2 cipher list (AEAD + forward
// secrecy only). It is ignored when MinVersion is 1.3 (1.3 suites are fixed).
var hardenedTLS12Ciphers = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
}

// applyTLSHardening sets the minimum version, a hardened cipher list, and inbound
// mTLS (client certificate verification) on tlsCfg according to cfg.
func applyTLSHardening(tlsCfg *tls.Config, cfg config.TLSConfig) error {
	switch strings.TrimSpace(cfg.MinVersion) {
	case "1.3":
		if len(cfg.CipherSuites) != 0 {
			return fmt.Errorf("cipher_suites cannot be configured when min_version is 1.3")
		}
		tlsCfg.MinVersion = tls.VersionTLS13
	default: // "" or "1.2"
		tlsCfg.MinVersion = tls.VersionTLS12
		ciphers, err := resolveCipherSuites(cfg.CipherSuites)
		if err != nil {
			return err
		}
		tlsCfg.CipherSuites = ciphers
	}

	if strings.TrimSpace(cfg.ClientCAFile) != "" {
		pem, err := os.ReadFile(cfg.ClientCAFile)
		if err != nil {
			return fmt.Errorf("read client_ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return fmt.Errorf("no valid certificates in client_ca_file %q", cfg.ClientCAFile)
		}
		tlsCfg.ClientCAs = pool
		switch strings.ToLower(strings.TrimSpace(cfg.ClientAuth)) {
		case "request":
			tlsCfg.ClientAuth = tls.RequestClientCert
		case "verify_if_given":
			tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
		default: // "" or "require"
			tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
		}
	}
	return nil
}

func resolveCipherSuites(names []string) ([]uint16, error) {
	if len(names) == 0 {
		return append([]uint16(nil), hardenedTLS12Ciphers...), nil
	}
	supported := make(map[string]uint16)
	allowedIDs := make(map[uint16]struct{}, len(hardenedTLS12Ciphers))
	for _, id := range hardenedTLS12Ciphers {
		allowedIDs[id] = struct{}{}
	}
	for _, suite := range tls.CipherSuites() {
		if _, ok := allowedIDs[suite.ID]; ok {
			supported[suite.Name] = suite.ID
		}
	}
	resolved := make([]uint16, 0, len(names))
	seen := make(map[uint16]struct{}, len(names))
	for i, rawName := range names {
		name := strings.TrimSpace(rawName)
		id, ok := supported[name]
		if !ok {
			return nil, fmt.Errorf("cipher_suites[%d]: unsupported or insecure TLS 1.2 cipher %q", i, rawName)
		}
		if _, duplicate := seen[id]; duplicate {
			return nil, fmt.Errorf("cipher_suites[%d]: duplicate cipher %q", i, rawName)
		}
		seen[id] = struct{}{}
		resolved = append(resolved, id)
	}
	return resolved, nil
}

// relayManagedHeaders are identity/hop headers that only Relay's own middleware
// or proxy may set. They are always stripped from inbound requests at the edge
// so a client can never spoof an authenticated identity to a backend.
var relayManagedHeaders = []string{
	"X-Authenticated-Sub",
	"X-Token-Scope",
	"X-Internal-Auth",
	"X-Admin",
	"X-Real-IP",
	"X-Relay-Client-Cert-Subject",
	"X-Relay-Client-Cert-San-Dns",
	"X-Relay-Client-Cert-San-Email",
	"X-Relay-Client-Cert-San-Ip",
	"X-Relay-Client-Cert-San-Uri",
	"X-Relay-Client-Cert-Fingerprint-Sha256",
}

// forwardedHeaders are stripped from inbound requests unless the immediate peer
// is a trusted proxy, in which case they are preserved (the proxy is the
// authority for the forwarding chain and scheme).
var forwardedHeaders = []string{
	"X-Forwarded-For",
	"X-Forwarded-Host",
	"X-Forwarded-Proto",
	"X-Forwarded-Port",
}

// stripUntrustedHeaders removes headers a client must not be able to spoof.
// Relay-managed identity headers (and any operator-configured extras) are always
// removed; the X-Forwarded-* family is removed only when the peer is not a
// trusted proxy. Client IP must already be resolved before this runs.
func stripUntrustedHeaders(r *http.Request, trustedNets []*net.IPNet, extra []string) {
	for _, h := range relayManagedHeaders {
		r.Header.Del(h)
	}
	for _, h := range extra {
		r.Header.Del(h)
	}
	// RFC 7239 values are generated by Relay when explicitly enabled. Even a
	// trusted proxy cannot inject a value that Relay would then endorse.
	r.Header.Del("Forwarded")
	if !httpx.PeerTrusted(r, trustedNets) {
		for _, h := range forwardedHeaders {
			r.Header.Del(h)
		}
	}
}

// h2cServerProtocols enables HTTP/1.1 plus cleartext HTTP/2 (h2c) on the
// plaintext listener so gRPC and other HTTP/2 clients can connect without TLS.
func h2cServerProtocols() *http.Protocols {
	p := new(http.Protocols)
	p.SetHTTP1(true)
	p.SetUnencryptedHTTP2(true)
	return p
}

// isLoopbackPeer reports whether the immediate TCP peer is a loopback address.
// It uses the real peer (RemoteAddr), so it cannot be bypassed via forwarding
// headers.
func isLoopbackPeer(r *http.Request) bool {
	ip := net.ParseIP(httpx.PeerIP(r))
	return ip != nil && ip.IsLoopback()
}

// metricsPeerAllowed reports whether the request may reach the metrics/Prometheus
// endpoints: always for a loopback peer, and for any peer within the configured
// scrape CIDRs. The check uses the real TCP peer, so it cannot be spoofed via
// forwarding headers.
func metricsPeerAllowed(r *http.Request, allowedNets []*net.IPNet) bool {
	return isLoopbackPeer(r) || httpx.PeerTrusted(r, allowedNets)
}

// writeReadiness reports whether the gateway can serve traffic: ready (200) when
// there are no backends or at least one backend has a healthy instance; not
// ready (503) when backends exist but none can serve. Intended for a k8s
// readiness probe.
func writeReadiness(w http.ResponseWriter, px *proxy.Proxy, policy config.ReadinessPolicyConfig) {
	evaluation := px.EvaluateReadiness(policy)
	w.Header().Set("Content-Type", "application/json")
	if !evaluation.Ready {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"status":"not_ready"}`))
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ready"}`))
}

func allowHealthRequest(w http.ResponseWriter, r *http.Request, access *admin.AccessControl) bool {
	if access == nil {
		return true
	}
	switch status := access.Status(r); status {
	case 0:
		return true
	case http.StatusUnauthorized:
		httpx.WriteError(w, status, "unauthorized")
	default:
		httpx.WriteError(w, http.StatusForbidden, "forbidden")
	}
	return false
}

// httpsRedirectHandler redirects only to a configured or allowlisted authority.
// It never reflects an arbitrary request Host into Location.
func httpsRedirectHandler(cfg config.HTTPConfig, httpsPort int) http.Handler {
	canonicalHost := normalizeConfiguredRedirectHost(cfg.CanonicalHost)
	allowedHosts := make(map[string]struct{}, len(cfg.RedirectAllowedHosts))
	for _, host := range cfg.RedirectAllowedHosts {
		allowedHosts[normalizeConfiguredRedirectHost(host)] = struct{}{}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestHost, ok := requestHostname(r.Host)
		if !ok {
			http.Error(w, "invalid Host header", http.StatusBadRequest)
			return
		}
		if len(allowedHosts) > 0 {
			if _, ok := allowedHosts[requestHost]; !ok {
				http.Error(w, "Host header is not allowed", http.StatusBadRequest)
				return
			}
		}
		targetHost := canonicalHost
		if targetHost == "" {
			if _, ok := allowedHosts[requestHost]; !ok {
				http.Error(w, "Host header is not allowed", http.StatusBadRequest)
				return
			}
			targetHost = requestHost
		}

		targetURL := *r.URL
		targetURL.Scheme = "https"
		targetURL.Host = httpsAuthority(targetHost, httpsPort)
		targetURL.User = nil
		targetURL.Opaque = ""
		if targetURL.Path == "" {
			targetURL.Path = "/"
		}
		w.Header().Set("Location", targetURL.String())
		w.WriteHeader(http.StatusMovedPermanently)
	})
}

func normalizeConfiguredRedirectHost(host string) string {
	host = strings.TrimSpace(host)
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

func requestHostname(authority string) (string, bool) {
	if authority == "" || strings.ContainsAny(authority, "/\\@?# \t\r\n") {
		return "", false
	}
	host := authority
	if parsed, _, err := net.SplitHostPort(authority); err == nil {
		host = parsed
	} else {
		switch {
		case strings.HasPrefix(authority, "[") && strings.HasSuffix(authority, "]"):
			host = authority[1 : len(authority)-1]
		case net.ParseIP(authority) != nil:
			host = authority
		case strings.Contains(authority, ":"):
			return "", false
		}
	}
	host = normalizeConfiguredRedirectHost(host)
	return host, host != ""
}

func httpsAuthority(host string, port int) string {
	if port != 443 {
		return net.JoinHostPort(host, fmt.Sprintf("%d", port))
	}
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}
