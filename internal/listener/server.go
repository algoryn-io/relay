package listener

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"algoryn.io/relay/internal/config"
	"algoryn.io/relay/internal/httpx"
	"algoryn.io/relay/internal/middleware"
	"algoryn.io/relay/internal/observability"
	"algoryn.io/relay/internal/proxy"
	"algoryn.io/relay/internal/router"
)

type Server struct {
	httpServer *http.Server
	proxy      *proxy.Proxy
	router     *router.Router
	logger     *slog.Logger
	metrics    *observability.Metrics
	metricsH   http.Handler
	routes     map[string]*compiledRoute
}

type compiledRoute struct {
	route   *config.RouteRuntime
	handler http.Handler
}

func New(listenerCfg config.ListenerConfig, rt *config.RuntimeConfig, logger *slog.Logger) (*Server, error) {
	if rt == nil {
		return nil, fmt.Errorf("runtime config must not be nil")
	}
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
	rtProxy, err := proxy.New(rt)
	if err != nil {
		return nil, err
	}
	mwRegistry, err := middleware.BuildRegistry(rt.Middleware)
	if err != nil {
		return nil, err
	}
	metrics := observability.NewMetrics(100)
	compiledRoutes := make(map[string]*compiledRoute, len(rt.Routes))
	for routeName, routeRuntime := range rt.Routes {
		route := routeRuntime
		routeRef := &route

		final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rtProxy.ServeHTTP(w, r, routeRef)
		})
		routeMiddlewares, resolveErr := middleware.Resolve(routeRef.MiddlewareRefs, mwRegistry)
		if resolveErr != nil {
			return nil, fmt.Errorf("resolve middleware for route %q: %w", routeRef.Name, resolveErr)
		}
		routeHandler := middleware.Chain(final, routeMiddlewares...)
		recoveryMW := middleware.Recovery(logger)
		loggingMW := observability.NewLoggingMiddleware(logger, routeRef.Name, routeRef.BackendName)
		metricsMW := observability.NewMetricsMiddleware(metrics, routeRef.Name)

		compiledRoutes[routeName] = &compiledRoute{
			route:   routeRef,
			handler: middleware.Chain(routeHandler, recoveryMW, loggingMW, metricsMW),
		}
	}

	s := &Server{
		proxy:    rtProxy,
		router:   rtRouter,
		logger:   logger,
		metrics:  metrics,
		metricsH: observability.MetricsHandler(metrics),
		routes:   compiledRoutes,
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

func (s *Server) Start() error {
	err := s.httpServer.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s == nil || s.httpServer == nil {
		return nil
	}
	if s.proxy != nil {
		s.proxy.Close()
	}
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path == "/_relay/metrics" {
		clientIP := httpx.ClientIP(req)
		if clientIP != "127.0.0.1" && clientIP != "::1" {
			httpx.WriteError(w, http.StatusForbidden, "forbidden")
			return
		}
		s.metricsH.ServeHTTP(w, req)
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
