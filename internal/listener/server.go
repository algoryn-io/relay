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
	proxy              *proxy.Proxy
	router             *router.Router
	metrics            *observability.Metrics
	metricsH           http.Handler
	prometheusH        http.Handler
	prometheus         *observability.PrometheusCollector
	prometheusPath     string
	metricsAllowedNets []*net.IPNet // extra peers (beyond loopback) allowed to scrape metrics
	routes             map[string]*compiledRoute
	trustedNets        []*net.IPNet
	fabricDispatch     *observability.EventDispatcher
	relayServiceName   string
	adminH             http.Handler
	stripHeaders       []string // extra inbound headers to remove at the edge
	owner              *resourceOwner

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
	httpsServer  *http.Server  // nil when HTTPS is not configured
	certReloader *CertReloader // non-nil only in manual TLS mode
	logger       *slog.Logger
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
func New(cfg *config.Config, rt *config.RuntimeConfig, logger *slog.Logger) (*Server, error) {
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

	st, err := buildState(cfg, rt, logger)
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
		connectionLimiter: newConnectionLimiter(cfg.Listener.MaxConnectionsPerIP),
		shutdownDone:      make(chan struct{}),
		states:            make(map[*serverState]struct{}),
		drainTimeout:      defaultStateDrainTimeout,
	}
	st.onClose = func() { s.removeState(st) }
	s.states[st] = struct{}{}
	s.state.Store(st)
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
		tlsCfg, reloader, err := buildTLSConfig(cfg.Listener.HTTPS.TLS)
		if err != nil {
			return nil, fmt.Errorf("tls config: %w", err)
		}
		s.certReloader = reloader // nil for auto mode; non-nil for manual mode
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

	newState, err := buildState(cfg, rt, s.logger)
	if err != nil {
		return fmt.Errorf("build reloaded state: %w", err)
	}
	newState.onClose = func() { s.removeState(newState) }
	s.states[newState] = struct{}{}

	old := s.state.Swap(newState)
	old.retire(s.drainTimeout)

	s.connectionLimiter.setLimit(cfg.Listener.MaxConnectionsPerIP)
	s.connectionLimiter.setMetrics(newState.prometheus)
	s.maxInFlight.Store(int64(cfg.Listener.MaxConcurrentRequests))
	s.maxRequestBodyBytes.Store(cfg.Listener.MaxRequestBodyBytes)

	// Rotate the TLS certificate when running in manual mode. A failure here
	// is non-fatal: the server keeps the previous certificate in service and
	// logs a warning so operators know the rotation did not take effect.
	if s.certReloader != nil {
		tlsCfg := cfg.Listener.HTTPS.TLS
		if rotateErr := s.certReloader.Reload(tlsCfg.CertFile, tlsCfg.KeyFile); rotateErr != nil {
			s.logger.Warn("TLS certificate reload failed, keeping current certificate",
				"cert_file", tlsCfg.CertFile,
				"error", rotateErr,
			)
		} else {
			s.logger.Info("TLS certificate reloaded", "cert_file", tlsCfg.CertFile)
		}
	}

	return nil
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
	req = httpx.WithResolvedClientIP(req, st.trustedNets)
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
		// Liveness: the process is up and serving.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
		return
	case req.URL.Path == "/_relay/ready":
		writeReadiness(w, st.proxy)
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

	metrics := observability.NewMetrics(100)
	promCollector := observability.NewPrometheusCollector()
	mwRegistry, mwClosers, err := middleware.BuildRegistry(rt.Middleware, logger, promCollector)
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
		loggingMW := observability.NewLoggingMiddleware(logger, routeRef.Name, routeRef.BackendName)
		metricsMW := observability.NewMetricsMiddlewareFabric(metrics, promCollector, fabricDispatch, relaySvc, routeRef.Name)
		tracingMW := observability.NewTracingMiddleware(routeRef.Name, routeRef.BackendName)

		compiledRoutes[routeName] = &compiledRoute{
			route:   routeRef,
			handler: middleware.Chain(routeHandler, recoveryMW, requestIDMW, loggingMW, metricsMW, tracingMW),
		}
	}

	trustedNets := httpx.ParseTrustedNets(cfg.Listener.TrustedProxies)

	promPath := cfg.Observability.Prometheus.Path
	if promPath == "" {
		promPath = "/_relay/metrics/prometheus"
	}

	adminH := admin.New(rtProxy, rt.Routes, cfg.Listener.Admin.AllowedCIDRs, cfg.Listener.Admin.ResolvedToken, logger)

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
		stripHeaders:       cfg.Listener.StripRequestHeaders,
		owner:              owner,
		drained:            make(chan struct{}),
		done:               make(chan struct{}),
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

// buildTLSConfig returns a *tls.Config for the given TLSConfig and, when the
// mode is "manual", a *CertReloader that can hot-swap the certificate without
// restarting the server. The reloader is nil for mode "auto".
//
// mode "manual": certificate is loaded from files via CertReloader; calling
//
//	CertReloader.Reload replaces the certificate for all subsequent handshakes.
//
// mode "auto":   uses autocert (Let's Encrypt) with an in-memory cache; cert
//
//	renewal is handled automatically by the ACME library.
func buildTLSConfig(cfg config.TLSConfig) (*tls.Config, *CertReloader, error) {
	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	if mode == "" {
		mode = "manual"
	}

	switch mode {
	case "manual":
		reloader, err := NewCertReloader(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, nil, fmt.Errorf("load cert/key: %w", err)
		}
		tlsCfg := &tls.Config{
			// GetCertificate is called on every TLS handshake, so swapping the
			// cert inside CertReloader takes effect for all new connections
			// immediately, with no listener restart required.
			GetCertificate: reloader.GetCertificate,
		}
		if err := applyTLSHardening(tlsCfg, cfg); err != nil {
			return nil, nil, err
		}
		return tlsCfg, reloader, nil

	case "auto":
		cacheDir := strings.TrimSpace(cfg.ACMECacheDir)
		if cacheDir == "" {
			return nil, nil, fmt.Errorf("acme_cache_dir is required when tls.mode is auto")
		}
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(cfg.Domains...),
			Cache:      autocert.DirCache(cacheDir),
		}
		tlsCfg := m.TLSConfig()
		if err := applyTLSHardening(tlsCfg, cfg); err != nil {
			return nil, nil, err
		}
		return tlsCfg, nil, nil

	default:
		return nil, nil, fmt.Errorf("unknown TLS mode %q", mode)
	}
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
		tlsCfg.MinVersion = tls.VersionTLS13
	default: // "" or "1.2"
		tlsCfg.MinVersion = tls.VersionTLS12
		tlsCfg.CipherSuites = hardenedTLS12Ciphers
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

// relayManagedHeaders are identity/hop headers that only Relay's own middleware
// or proxy may set. They are always stripped from inbound requests at the edge
// so a client can never spoof an authenticated identity to a backend.
var relayManagedHeaders = []string{
	"X-Authenticated-Sub",
	"X-Token-Scope",
	"X-Internal-Auth",
	"X-Admin",
	"X-Real-IP",
}

// forwardedHeaders are stripped from inbound requests unless the immediate peer
// is a trusted proxy, in which case they are preserved (the proxy is the
// authority for the forwarding chain and scheme).
var forwardedHeaders = []string{
	"X-Forwarded-For",
	"X-Forwarded-Host",
	"X-Forwarded-Proto",
	"X-Forwarded-Port",
	"Forwarded",
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
func writeReadiness(w http.ResponseWriter, px *proxy.Proxy) {
	healthy, total := px.Readiness()
	w.Header().Set("Content-Type", "application/json")
	if total > 0 && healthy == 0 {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"status":"unavailable"}`))
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ready"}`))
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
