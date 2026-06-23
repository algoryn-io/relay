package listener

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
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
)

// serverState holds all hot-reloadable request-handling state.
// It is swapped atomically on reload; the previous state is closed after the swap.
type serverState struct {
	proxy            *proxy.Proxy
	router           *router.Router
	metrics          *observability.Metrics
	metricsH         http.Handler
	prometheusH      http.Handler
	prometheusPath   string
	routes           map[string]*compiledRoute
	trustedNets      []*net.IPNet
	fabricDispatch   *observability.EventDispatcher
	relayServiceName string
	adminH           http.Handler
	stripHeaders     []string    // extra inbound headers to remove at the edge
	mwClosers        []io.Closer // middleware resources (redis pools, prune loops)
}

func (st *serverState) close() {
	if st == nil {
		return
	}
	if st.fabricDispatch != nil {
		st.fabricDispatch.Close()
	}
	if st.proxy != nil {
		st.proxy.Close()
	}
	middleware.CloseAll(st.mwClosers)
}

type Server struct {
	httpServer   *http.Server
	httpsServer  *http.Server  // nil when HTTPS is not configured
	certReloader *CertReloader // non-nil only in manual TLS mode
	logger       *slog.Logger
	state        atomic.Pointer[serverState]
	reloadMu     sync.Mutex

	inFlight    atomic.Int64 // currently in-flight proxied requests
	maxInFlight atomic.Int64 // global cap; 0 = unlimited (resizable on reload)
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

	s := &Server{logger: logger}
	s.state.Store(st)
	s.maxInFlight.Store(int64(cfg.Listener.MaxConcurrentRequests))

	timeouts := cfg.Listener.Timeouts
	httpsPort := cfg.Listener.HTTPS.Port

	readHeaderTimeout := timeouts.ReadHeader
	if readHeaderTimeout <= 0 {
		readHeaderTimeout = defaultReadHeaderTimeout
	}

	// HTTP server: either serves requests directly, or redirects to HTTPS.
	httpHandler := http.Handler(s)
	if httpsPort > 0 && cfg.Listener.HTTP.Port > 0 {
		httpHandler = httpsRedirectHandler(httpsPort)
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
		}
		// When only HTTPS is configured, the HTTP server is nil; Start() still
		// works because it only starts the servers that are non-nil.
	}

	return s, nil
}

// Reload applies a new config without restarting the process. The TCP listener
// stays open; only the request-handling state (routes, backends, middleware,
// metrics) is replaced. In-flight requests on the old state complete normally.
// Returns an error if the new state cannot be built; the server keeps running
// with the previous config in that case.
func (s *Server) Reload(cfg *config.Config, rt *config.RuntimeConfig) error {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()

	newState, err := buildState(cfg, rt, s.logger)
	if err != nil {
		return fmt.Errorf("build reloaded state: %w", err)
	}

	old := s.state.Swap(newState)
	go old.close()

	s.maxInFlight.Store(int64(cfg.Listener.MaxConcurrentRequests))

	for _, srv := range []*http.Server{s.httpServer, s.httpsServer} {
		if srv == nil {
			continue
		}
		srv.ReadTimeout = cfg.Listener.Timeouts.Read
		srv.WriteTimeout = cfg.Listener.Timeouts.Write
		srv.IdleTimeout = cfg.Listener.Timeouts.Idle
	}

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
	s.state.Load().close()
	return firstErr
}

func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	st := s.state.Load()

	// Resolve the client IP (honoring trusted proxies) into the request context
	// first, then strip spoofable inbound headers. Resolution happens before the
	// strip so removing X-Forwarded-* here never affects client-IP resolution.
	req = httpx.WithResolvedClientIP(req, st.trustedNets)
	stripUntrustedHeaders(req, st.trustedNets, st.stripHeaders)

	switch {
	case req.URL.Path == "/_relay/metrics":
		// Gate on the real TCP peer, not the (spoofable) forwarded client IP.
		if !isLoopbackPeer(req) {
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
		// Same exposure as the JSON metrics endpoint: restrict to the local peer.
		if !isLoopbackPeer(req) {
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

func buildState(cfg *config.Config, rt *config.RuntimeConfig, logger *slog.Logger) (*serverState, error) {
	rtRouter, err := router.New(rt)
	if err != nil {
		return nil, err
	}
	rtProxy, err := proxy.New(rt, logger)
	if err != nil {
		return nil, err
	}
	rtProxy.SetWebSocketIdleTimeout(cfg.Listener.Timeouts.WebSocketIdle)
	mwRegistry, mwClosers, err := middleware.BuildRegistry(rt.Middleware, logger)
	if err != nil {
		return nil, err
	}

	metrics := observability.NewMetrics(100)
	promCollector := observability.NewPrometheusCollector()
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
			rtProxy.Close()
			middleware.CloseAll(mwClosers)
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

	st := &serverState{
		proxy:            rtProxy,
		router:           rtRouter,
		metrics:          metrics,
		metricsH:         observability.MetricsHandler(metrics),
		prometheusH:      promCollector.Handler(),
		prometheusPath:   promPath,
		routes:           compiledRoutes,
		trustedNets:      trustedNets,
		fabricDispatch:   fabricDispatch,
		relayServiceName: relaySvc,
		adminH:           adminH,
		stripHeaders:     cfg.Listener.StripRequestHeaders,
		mwClosers:        mwClosers,
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
			MinVersion:     tls.VersionTLS12,
		}
		return tlsCfg, reloader, nil

	case "auto":
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(cfg.Domains...),
			Cache:      autocert.DirCache(".autocert-cache"),
		}
		return m.TLSConfig(), nil, nil

	default:
		return nil, nil, fmt.Errorf("unknown TLS mode %q", mode)
	}
}

// relayManagedHeaders are identity/hop headers that only Relay's own middleware
// or proxy may set. They are always stripped from inbound requests at the edge
// so a client can never spoof an authenticated identity to a backend.
var relayManagedHeaders = []string{
	"X-Authenticated-Sub",
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

// isLoopbackPeer reports whether the immediate TCP peer is a loopback address.
// It uses the real peer (RemoteAddr), so it cannot be bypassed via forwarding
// headers.
func isLoopbackPeer(r *http.Request) bool {
	ip := net.ParseIP(httpx.PeerIP(r))
	return ip != nil && ip.IsLoopback()
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

// httpsRedirectHandler returns an http.Handler that permanently redirects
// every request to the same path on the HTTPS port.
func httpsRedirectHandler(httpsPort int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if host == "" {
			host = r.URL.Host
		}
		// Strip any existing port from the host.
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		target := fmt.Sprintf("https://%s:%d%s", host, httpsPort, r.RequestURI)
		if httpsPort == 443 {
			target = fmt.Sprintf("https://%s%s", host, r.RequestURI)
		}
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	})
}
