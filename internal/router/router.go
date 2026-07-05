package router

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"algoryn.io/relay/internal/config"
)

var (
	ErrNotFound         = errors.New("route not found")
	ErrMethodNotAllowed = errors.New("method not allowed")
)

type Router struct {
	// exact maps an exact path to the routes registered for it, ordered by
	// descending specificity so a host/header/query-constrained route is tried
	// before a catch-all sharing the same path.
	exact map[string][]*config.RouteRuntime
	// prefixes are ordered by descending prefix length, then descending
	// specificity, so the longest and most specific prefix wins.
	prefixes []*config.RouteRuntime
	// hasQueryRoutes is true when at least one route constrains query
	// parameters, so Match only parses the query string when it can matter.
	hasQueryRoutes bool
}

func New(rt *config.RuntimeConfig) (*Router, error) {
	if rt == nil {
		return nil, fmt.Errorf("runtime config is nil")
	}

	r := &Router{
		exact: make(map[string][]*config.RouteRuntime),
	}

	seenExact := make(map[string]struct{})
	seenPrefix := make(map[string]struct{})

	for name := range rt.Routes {
		route := rt.Routes[name]
		routeCopy := route

		if len(routeCopy.QueryMatch) > 0 {
			r.hasQueryRoutes = true
		}

		if routeCopy.PathPrefix != "" {
			key := routeCopy.PathPrefix + "\x00" + matchSignature(&routeCopy)
			if _, dup := seenPrefix[key]; dup {
				return nil, fmt.Errorf("duplicate path_prefix %q with the same host/header/query match", routeCopy.PathPrefix)
			}
			seenPrefix[key] = struct{}{}
			r.prefixes = append(r.prefixes, &routeCopy)
			continue
		}

		if routeCopy.Path == "" {
			return nil, fmt.Errorf("route %q has empty path", routeCopy.Name)
		}

		sig := matchSignature(&routeCopy)
		for _, method := range routeCopy.Methods {
			key := routeCopy.Path + "\x00" + method + "\x00" + sig
			if _, dup := seenExact[key]; dup {
				return nil, fmt.Errorf("duplicate route match for path %q and method %q with the same host/header/query match", routeCopy.Path, method)
			}
			seenExact[key] = struct{}{}
		}
		r.exact[routeCopy.Path] = append(r.exact[routeCopy.Path], &routeCopy)
	}

	for path := range r.exact {
		candidates := r.exact[path]
		sort.SliceStable(candidates, func(i, j int) bool {
			return candidates[i].Specificity > candidates[j].Specificity
		})
		r.exact[path] = candidates
	}

	sort.SliceStable(r.prefixes, func(i, j int) bool {
		li, lj := len(r.prefixes[i].PathPrefix), len(r.prefixes[j].PathPrefix)
		if li != lj {
			return li > lj
		}
		return r.prefixes[i].Specificity > r.prefixes[j].Specificity
	})

	return r, nil
}

// matchSignature returns a canonical string identifying a route's host, header,
// and query predicates. Two routes with the same signature on the same path (or
// prefix) collide and are rejected as duplicates.
func matchSignature(route *config.RouteRuntime) string {
	var b strings.Builder
	b.WriteString("h:")
	b.WriteString(strings.Join(sortedKeys(route.HostSet), ","))
	b.WriteString("|hdr:")
	b.WriteString(joinKV(route.HeaderMatch))
	b.WriteString("|q:")
	b.WriteString(joinKV(route.QueryMatch))
	return b.String()
}

func sortedKeys(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func joinKV(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+m[k])
	}
	return strings.Join(parts, ",")
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

// matchPredicates reports whether the route's host, header, and query
// constraints are all satisfied by the request. Method is checked separately so
// the router can distinguish "no route" (404) from "wrong method" (405). When a
// route has no predicates configured, this always returns true, preserving the
// original path+method matching behavior.
func matchPredicates(route *config.RouteRuntime, r *http.Request, host string, query url.Values) bool {
	if len(route.HostSet) > 0 {
		if _, ok := route.HostSet[host]; !ok {
			return false
		}
	}
	for name, want := range route.HeaderMatch {
		if r.Header.Get(name) != want {
			return false
		}
	}
	for name, want := range route.QueryMatch {
		if query.Get(name) != want {
			return false
		}
	}
	return true
}

// normalizeHost lowercases the request host and strips any port so it can be
// compared against configured hosts.
func normalizeHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(raw); err == nil {
		raw = h
	}
	return strings.ToLower(raw)
}

func (r *Router) Match(req *http.Request) (*config.RouteRuntime, error) {
	if r == nil {
		return nil, fmt.Errorf("router is nil")
	}
	if req == nil {
		return nil, fmt.Errorf("request is nil")
	}

	path := req.URL.Path
	host := normalizeHost(req.Host)

	var query url.Values
	if r.hasQueryRoutes {
		query = req.URL.Query()
	}

	if candidates, ok := r.exact[path]; ok {
		predicateMatched := false
		for _, route := range candidates {
			if !matchPredicates(route, req, host, query) {
				continue
			}
			if routeAllowsMethod(route, req.Method) {
				return route, nil
			}
			predicateMatched = true
		}
		if predicateMatched {
			return nil, ErrMethodNotAllowed
		}
		return nil, ErrNotFound
	}

	for _, route := range r.prefixes {
		if !pathMatchesPrefix(path, route.PathPrefix) {
			continue
		}
		if !matchPredicates(route, req, host, query) {
			continue
		}
		if routeAllowsMethod(route, req.Method) {
			return route, nil
		}
		return nil, ErrMethodNotAllowed
	}

	return nil, ErrNotFound
}
