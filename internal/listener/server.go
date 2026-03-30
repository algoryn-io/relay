package listener

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"algoryn.io/relay/internal/config"
	"algoryn.io/relay/internal/middleware"
	"algoryn.io/relay/internal/proxy"
	"algoryn.io/relay/internal/router"
)

type Server struct {
	httpServer *http.Server
	proxy      *proxy.Proxy
	router     *router.Router
	logger     *slog.Logger
	routes     map[string]*compiledRoute
}

type compiledRoute struct {
	route   *config.RouteRuntime
	handler http.Handler
}

type responseBody struct {
	Route   string `json:"route,omitempty"`
	Backend string `json:"backend,omitempty"`
	Status  string `json:"status,omitempty"`
	Error   string `json:"error,omitempty"`
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

		compiledRoutes[routeName] = &compiledRoute{
			route:   routeRef,
			handler: middleware.Chain(final, routeMiddlewares...),
		}
	}

	s := &Server{
		proxy:  rtProxy,
		router: rtRouter,
		logger: logger,
		routes: compiledRoutes,
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
	route, err := s.router.Match(req)
	switch {
	case err == nil:
		compiled, ok := s.routes[route.Name]
		if !ok || compiled == nil || compiled.handler == nil {
			s.logger.Error("compiled route not found", "route", route.Name)
			s.writeJSON(w, http.StatusInternalServerError, responseBody{
				Error:  "internal_error",
				Status: "error",
			})
			return
		}
		compiled.handler.ServeHTTP(w, req)
	case errors.Is(err, router.ErrMethodNotAllowed):
		s.writeJSON(w, http.StatusMethodNotAllowed, responseBody{
			Error:  "method_not_allowed",
			Status: "error",
		})
	case errors.Is(err, router.ErrNotFound):
		s.writeJSON(w, http.StatusNotFound, responseBody{
			Error:  "not_found",
			Status: "error",
		})
	default:
		s.logger.Error("request match failed", "error", err)
		s.writeJSON(w, http.StatusInternalServerError, responseBody{
			Error:  "internal_error",
			Status: "error",
		})
	}
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, payload responseBody) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil && s.logger != nil {
		s.logger.Error("failed to write JSON response", "error", err)
	}
}
