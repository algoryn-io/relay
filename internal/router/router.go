package router

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"algoryn.io/relay/internal/config"
)

var (
	ErrNotFound         = errors.New("route not found")
	ErrMethodNotAllowed = errors.New("method not allowed")
)

type Router struct {
	exact    map[string]map[string]*config.RouteRuntime
	prefixes []*config.RouteRuntime
}

func New(rt *config.RuntimeConfig) (*Router, error) {
	if rt == nil {
		return nil, fmt.Errorf("runtime config is nil")
	}

	r := &Router{
		exact: make(map[string]map[string]*config.RouteRuntime),
	}

	seenPrefix := make(map[string]struct{})

	for name := range rt.Routes {
		route := rt.Routes[name]
		routeCopy := route

		if routeCopy.PathPrefix != "" {
			if _, dup := seenPrefix[routeCopy.PathPrefix]; dup {
				return nil, fmt.Errorf("duplicate path_prefix %q", routeCopy.PathPrefix)
			}
			seenPrefix[routeCopy.PathPrefix] = struct{}{}
			r.prefixes = append(r.prefixes, &routeCopy)
			continue
		}

		if routeCopy.Path == "" {
			return nil, fmt.Errorf("route %q has empty path", routeCopy.Name)
		}

		methods, ok := r.exact[routeCopy.Path]
		if !ok {
			methods = make(map[string]*config.RouteRuntime)
			r.exact[routeCopy.Path] = methods
		}

		for _, method := range routeCopy.Methods {
			if existing, exists := methods[method]; exists {
				return nil, fmt.Errorf("duplicate route match for path %q and method %q: %q and %q", routeCopy.Path, method, existing.Name, routeCopy.Name)
			}
			methods[method] = &routeCopy
		}
	}

	sort.SliceStable(r.prefixes, func(i, j int) bool {
		return len(r.prefixes[i].PathPrefix) > len(r.prefixes[j].PathPrefix)
	})

	return r, nil
}

func pathMatchesPrefix(requestPath, prefix string) bool {
	if prefix == "" {
		return false
	}
	if requestPath == prefix {
		return true
	}
	if prefix == "/" {
		return strings.HasPrefix(requestPath, "/")
	}
	return strings.HasPrefix(requestPath, prefix+"/")
}

func routeAllowsMethod(route *config.RouteRuntime, method string) bool {
	if route == nil {
		return false
	}
	if len(route.MethodSet) > 0 {
		_, ok := route.MethodSet[method]
		return ok
	}
	for _, m := range route.Methods {
		if m == method {
			return true
		}
	}
	return false
}

func (r *Router) Match(req *http.Request) (*config.RouteRuntime, error) {
	if r == nil {
		return nil, fmt.Errorf("router is nil")
	}
	if req == nil {
		return nil, fmt.Errorf("request is nil")
	}

	path := req.URL.Path

	if methods, ok := r.exact[path]; ok {
		route, ok := methods[req.Method]
		if ok {
			return route, nil
		}
		return nil, ErrMethodNotAllowed
	}

	for _, route := range r.prefixes {
		if !pathMatchesPrefix(path, route.PathPrefix) {
			continue
		}
		if routeAllowsMethod(route, req.Method) {
			return route, nil
		}
		return nil, ErrMethodNotAllowed
	}

	return nil, ErrNotFound
}
