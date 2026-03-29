package router

import (
	"errors"
	"fmt"
	"net/http"

	"algoryn.io/relay/internal/config"
)

var (
	ErrNotFound         = errors.New("route not found")
	ErrMethodNotAllowed = errors.New("method not allowed")
)

type Router struct {
	paths map[string]map[string]*config.RouteRuntime
}

func New(rt *config.RuntimeConfig) (*Router, error) {
	if rt == nil {
		return nil, fmt.Errorf("runtime config is nil")
	}

	r := &Router{
		paths: make(map[string]map[string]*config.RouteRuntime, len(rt.Routes)),
	}

	for name := range rt.Routes {
		route := rt.Routes[name]
		methods, ok := r.paths[route.Path]
		if !ok {
			methods = make(map[string]*config.RouteRuntime, len(route.Methods))
			r.paths[route.Path] = methods
		}

		routeCopy := route
		for _, method := range route.Methods {
			if existing, exists := methods[method]; exists {
				return nil, fmt.Errorf("duplicate route match for path %q and method %q: %q and %q", route.Path, method, existing.Name, route.Name)
			}
			methods[method] = &routeCopy
		}
	}

	return r, nil
}

func (r *Router) Match(req *http.Request) (*config.RouteRuntime, error) {
	if r == nil {
		return nil, fmt.Errorf("router is nil")
	}
	if req == nil {
		return nil, fmt.Errorf("request is nil")
	}

	methods, ok := r.paths[req.URL.Path]
	if !ok {
		return nil, ErrNotFound
	}

	route, ok := methods[req.Method]
	if !ok {
		return nil, ErrMethodNotAllowed
	}

	return route, nil
}
