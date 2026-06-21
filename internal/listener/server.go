package listener

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/acme/autocert"

	"algoryn.io/relay/internal/config"
	"algoryn.io/relay/internal/httpx"
	"algoryn.io/relay/internal/middleware"
	"algoryn.io/relay/internal/observability"
	"algoryn.io/relay/internal/proxy"
	"algoryn.io/relay/internal/router"
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
}

type Server struct {
	httpServer  *http.Server
	httpsServer *http.Server // nil when HTTPS is not configured
	logger      *slog.Logger
	state       atomic.Pointer[serverState]
	reloadMu    sync.Mutex
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

	timeouts := cfg.Listener.Timeouts
	httpsPort := cfg.Listener.HTTPS.Port

	// HTTP server: either serves requests directly, or redirects to HTTPS.
	httpHandler := http.Handler(s)
	if httpsPort > 0 && cfg.Listener.HTTP.Port > 0 {
		httpHandler = httpsRedirectHandler(httpsPort)
	}

	if cfg.Listener.HTTP.Port > 0 {
		s.httpServer = &http.Server{
			Addr:         fmt.Sprintf(":%d", cfg.Listener.HTTP.Port),
			Handler:      httpHandler,
			ReadTimeout:  timeouts.Read,
			WriteTimeout: timeouts.Write,
			IdleTimeout:  timeouts.Idle,
		}
	}

	if httpsPort > 0 {
		tlsCfg, err := buildTLSConfig(cfg.Listener.HTTPS.TLS)
		if err != nil {
			return nil, fmt.Errorf("tls config: %w", err)
		}
		s.httpsServer = &http.Server{
			Addr:         fmt.Sprintf(":%d", httpsPort),
			Handler:      s,
			TLSConfig:    tlsCfg,
			ReadTimeout:  timeouts.Read,
			WriteTimeout: timeouts.Write,
			IdleTimeout:  timeouts.Idle,
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

	for _, srv := range []*http.Server{s.httpServer, s.httpsServer} {
		if srv == nil {
			continue
		}
		srv.ReadTimeout = cfg.Listener.Timeouts.Read
		srv.WriteTimeout = cfg.Listener.Timeouts.Write
		srv.IdleTimeout = cfg.Listener.Timeouts.Idle
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
	s.state.Load().close()
	var firstErr error
	for _, srv := range []*http.Server{s.httpServer, s.httpsServer} {
		if srv == nil {
			continue
		}
		if err := srv.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	st := s.state.Load()

	req = httpx.WithResolvedClientIP(req, st.trustedNets)

	switch req.URL.Path {
	case "/_relay/metrics":
		clientIP := httpx.ClientIP(req)
		if clientIP != "127.0.0.1" && clientIP != "::1" {
			httpx.WriteError(w, http.StatusForbidden, "forbidden")
			return
		}
		st.metricsH.ServeHTTP(w, req)
		return
	case "/_relay/health":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
		return
	case st.prometheusPath:
		st.prometheusH.ServeHTTP(w, req)
		return
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
	mwRegistry, err := middleware.BuildRegistry(rt.Middleware, logger)
	if err != nil {
		return nil, err
	}

	metrics := observability.NewMetrics(100)
	promCollector := observability.NewPrometheusCollector()
	rtProxy.SetHealthNotifier(promCollector)
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

// buildTLSConfig returns a *tls.Config for the given TLSConfig.
// mode "manual": loads cert and key from files.
// mode "auto":   uses autocert (Let's Encrypt) with an in-memory cache.
func buildTLSConfig(cfg config.TLSConfig) (*tls.Config, error) {
	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	if mode == "" {
		mode = "manual"
	}

	switch mode {
	case "manual":
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load cert/key: %w", err)
		}
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}, nil

	case "auto":
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(cfg.Domains...),
			Cache:      autocert.DirCache(".autocert-cache"),
		}
		return m.TLSConfig(), nil

	default:
		return nil, fmt.Errorf("unknown TLS mode %q", mode)
	}
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
