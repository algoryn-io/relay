package listener

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"algoryn.io/relay/internal/config"
	"algoryn.io/relay/internal/httpx"
	"algoryn.io/relay/internal/middleware"
	"algoryn.io/relay/internal/observability"
	"algoryn.io/relay/internal/proxy"
	"algoryn.io/relay/internal/router"
)

type Server struct {
	httpServer   *http.Server
	proxy        *proxy.Proxy
	router       *router.Router
	logger       *slog.Logger
	metrics      *observability.Metrics
	metricsH     http.Handler
	prometheusH  http.Handler
	prometheusPath string
	routes       map[string]*compiledRoute
	trustedNets  []*net.IPNet

	fabricDispatch   *observability.EventDispatcher
	relayServiceName string
}

type compiledRoute struct {
	route   *config.RouteRuntime
	handler http.Handler
}

// New builds an HTTP server. cfg must not be nil; cfg.Listener supplies bind and timeout settings.
func New(cfg *config.Config, rt *config.RuntimeConfig, logger *slog.Logger) (*Server, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config must not be nil")
	}
	if rt == nil {
		return nil, fmt.Errorf("runtime config must not be nil")
	}
	listenerCfg := cfg.Listener
	if listenerCfg.HTTP.Port <= 0 {
		return nil, fmt.Errorf("listener.http.port must be greater than 0")
	}
	if logger == nil {
		logger = slog.Default()
	}

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
	compiledRoutes := make(map[string]*compiledRoute, len(rt.Routes))

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

		compiledRoutes[routeName] = &compiledRoute{
			route:   routeRef,
			handler: middleware.Chain(routeHandler, recoveryMW, requestIDMW, loggingMW, metricsMW),
		}
	}

	trustedNets := httpx.ParseTrustedNets(cfg.Listener.TrustedProxies)

	promPath := cfg.Observability.Prometheus.Path
	if promPath == "" {
		promPath = "/_relay/metrics/prometheus"
	}

	s := &Server{
		proxy:            rtProxy,
		router:           rtRouter,
		logger:           logger,
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
		s.enqueueFabricBackendRegistryEvents(rt)
	}

	s.httpServer = &http.Server{
		Addr:         fmt.Sprintf(":%d", listenerCfg.HTTP.Port),
		Handler:      s,
		ReadTimeout:  listenerCfg.Timeouts.Read,
		WriteTimeout: listenerCfg.Timeouts.Write,
		IdleTimeout:  listenerCfg.Timeouts.Idle,
	}

	return s, nil
}

func (s *Server) enqueueFabricBackendRegistryEvents(rt *config.RuntimeConfig) {
	if s == nil || s.fabricDispatch == nil || rt == nil {
		return
	}
	for _, b := range rt.Backends {
		for _, inst := range b.Instances {
			if strings.TrimSpace(inst.URL) == "" {
				continue
			}
			evt := observability.BuildServiceRegisteredFabricEvent(s.relayServiceName, b.Name, inst.URL)
			s.fabricDispatch.TryEnqueue(observability.FabricDispatchItem{Event: evt})
		}
	}
}

func (s *Server) Start() error {
	err := s.httpServer.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s != nil && s.fabricDispatch != nil {
		s.fabricDispatch.Close()
		s.fabricDispatch = nil
	}
	if s == nil || s.httpServer == nil {
		return nil
	}
	if s.proxy != nil {
		s.proxy.Close()
	}
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	req = httpx.WithResolvedClientIP(req, s.trustedNets)

	switch req.URL.Path {
	case "/_relay/metrics":
		clientIP := httpx.ClientIP(req)
		if clientIP != "127.0.0.1" && clientIP != "::1" {
			httpx.WriteError(w, http.StatusForbidden, "forbidden")
			return
		}
		s.metricsH.ServeHTTP(w, req)
		return
	case "/_relay/health":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
		return
	case s.prometheusPath:
		s.prometheusH.ServeHTTP(w, req)
		return
	}

	route, err := s.router.Match(req)
	switch {
	case err == nil:
		compiled, ok := s.routes[route.Name]
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
