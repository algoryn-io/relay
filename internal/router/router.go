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
	// grpcExact maps /service/method paths for match.grpc routes (method set).
	grpcExact map[string][]*config.RouteRuntime
	// grpcPrefixes are match.grpc routes without a method (all methods on a
	// service), ordered by descending prefix length then specificity.
	grpcPrefixes []*config.RouteRuntime
	// globs are ordered by descending PatternRank (literal length), then
	// descending specificity. Evaluated after exact/prefix matches.
	globs []*config.RouteRuntime
	// regexes are ordered by descending PatternRank (pattern length), then
	// descending specificity. Evaluated last among path matchers.
	regexes []*config.RouteRuntime
	// hasQueryRoutes is true when at least one route constrains query
	// parameters, so Match only parses the query string when it can matter.
	hasQueryRoutes bool
}

func New(rt *config.RuntimeConfig) (*Router, error) {
	if rt == nil {
		return nil, fmt.Errorf("runtime config is nil")
	}

	r := &Router{
		exact:     make(map[string][]*config.RouteRuntime),
		grpcExact: make(map[string][]*config.RouteRuntime),
	}

	seenExact := make(map[string]struct{})
	seenPrefix := make(map[string]struct{})
	seenGRPCExact := make(map[string]struct{})
	seenGRPCPrefix := make(map[string]struct{})
	seenGlob := make(map[string]struct{})
	seenRegex := make(map[string]struct{})

	for name := range rt.Routes {
		route := rt.Routes[name]
		routeCopy := route

		if len(routeCopy.QueryMatch) > 0 {
			r.hasQueryRoutes = true
		}

		sig := matchSignature(&routeCopy)

		switch {
		case routeCopy.GRPC:
			if routeCopy.PathPrefix != "" {
				key := routeCopy.PathPrefix + "\x00" + sig
				if _, dup := seenGRPCPrefix[key]; dup {
					return nil, fmt.Errorf("duplicate grpc service %q with the same host/header/query match", routeCopy.GRPCService)
				}
				seenGRPCPrefix[key] = struct{}{}
				r.grpcPrefixes = append(r.grpcPrefixes, &routeCopy)
				continue
			}
			if routeCopy.Path == "" {
				return nil, fmt.Errorf("route %q has empty grpc path", routeCopy.Name)
			}
			for _, method := range routeCopy.Methods {
				key := routeCopy.Path + "\x00" + method + "\x00" + sig
				if _, dup := seenGRPCExact[key]; dup {
					return nil, fmt.Errorf("duplicate grpc route for path %q and method %q with the same host/header/query match", routeCopy.Path, method)
				}
				seenGRPCExact[key] = struct{}{}
			}
			r.grpcExact[routeCopy.Path] = append(r.grpcExact[routeCopy.Path], &routeCopy)
			continue

		case routeCopy.PathGlob != "":
			if routeCopy.PathGlobRe == nil {
				return nil, fmt.Errorf("route %q has path_glob without compiled pattern", routeCopy.Name)
			}
			key := routeCopy.PathGlob + "\x00" + sig
			if _, dup := seenGlob[key]; dup {
				return nil, fmt.Errorf("duplicate path_glob %q with the same host/header/query match", routeCopy.PathGlob)
			}
			seenGlob[key] = struct{}{}
			r.globs = append(r.globs, &routeCopy)
			continue

		case routeCopy.PathRegex != "":
			if routeCopy.PathRegexRe == nil {
				return nil, fmt.Errorf("route %q has path_regex without compiled pattern", routeCopy.Name)
			}
			key := routeCopy.PathRegex + "\x00" + sig
			if _, dup := seenRegex[key]; dup {
				return nil, fmt.Errorf("duplicate path_regex %q with the same host/header/query match", routeCopy.PathRegex)
			}
			seenRegex[key] = struct{}{}
			r.regexes = append(r.regexes, &routeCopy)
			continue

		case routeCopy.PathPrefix != "":
			key := routeCopy.PathPrefix + "\x00" + sig
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
	for path := range r.grpcExact {
		candidates := r.grpcExact[path]
		sort.SliceStable(candidates, func(i, j int) bool {
			return candidates[i].Specificity > candidates[j].Specificity
		})
		r.grpcExact[path] = candidates
	}

	sort.SliceStable(r.prefixes, func(i, j int) bool {
		li, lj := len(r.prefixes[i].PathPrefix), len(r.prefixes[j].PathPrefix)
		if li != lj {
			return li > lj
		}
		return r.prefixes[i].Specificity > r.prefixes[j].Specificity
	})
	sort.SliceStable(r.grpcPrefixes, func(i, j int) bool {
		li, lj := len(r.grpcPrefixes[i].PathPrefix), len(r.grpcPrefixes[j].PathPrefix)
		if li != lj {
			return li > lj
		}
		return r.grpcPrefixes[i].Specificity > r.grpcPrefixes[j].Specificity
	})

	sort.SliceStable(r.globs, func(i, j int) bool {
		if r.globs[i].PatternRank != r.globs[j].PatternRank {
			return r.globs[i].PatternRank > r.globs[j].PatternRank
		}
		return r.globs[i].Specificity > r.globs[j].Specificity
	})

	sort.SliceStable(r.regexes, func(i, j int) bool {
		if r.regexes[i].PatternRank != r.regexes[j].PatternRank {
			return r.regexes[i].PatternRank > r.regexes[j].PatternRank
		}
		return r.regexes[i].Specificity > r.regexes[j].Specificity
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

// isGRPCContentType reports whether ct is a gRPC content type
// (application/grpc or application/grpc+…).
func isGRPCContentType(ct string) bool {
	ct = strings.TrimSpace(ct)
	if ct == "" {
		return false
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	ct = strings.ToLower(ct)
	return ct == "application/grpc" || strings.HasPrefix(ct, "application/grpc+")
}

// matchPredicates reports whether the route's host, header, query, and (for
// gRPC routes) content-type constraints are all satisfied by the request.
// Method is checked separately so the router can distinguish "no route" (404)
// from "wrong method" (405). When a route has no predicates configured, this
// always returns true, preserving the original path+method matching behavior.
func matchPredicates(route *config.RouteRuntime, r *http.Request, host string, query url.Values) bool {
	if route.GRPC && !isGRPCContentType(r.Header.Get("Content-Type")) {
		return false
	}
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

// tryRoutes walks candidates that already matched on path shape. It returns the
// first route whose predicates and method match, ErrMethodNotAllowed when a
// predicate matched but the method did not, or ErrNotFound when nothing matched.
func tryRoutes(candidates []*config.RouteRuntime, req *http.Request, host string, query url.Values) (*config.RouteRuntime, error) {
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

	// gRPC routes are consulted first when the request looks like gRPC, so a
	// service/method rule wins over a broad HTTP prefix on the same path.
	// Non-gRPC requests skip these entries (content-type predicate) without
	// short-circuiting HTTP matchers.
	if isGRPCContentType(req.Header.Get("Content-Type")) {
		if candidates, ok := r.grpcExact[path]; ok {
			route, err := tryRoutes(candidates, req, host, query)
			if err == nil || errors.Is(err, ErrMethodNotAllowed) {
				return route, err
			}
		}
		var grpcPrefixHits []*config.RouteRuntime
		for _, route := range r.grpcPrefixes {
			if pathMatchesPrefix(path, route.PathPrefix) {
				grpcPrefixHits = append(grpcPrefixHits, route)
			}
		}
		if route, err := tryRoutes(grpcPrefixHits, req, host, query); err == nil || errors.Is(err, ErrMethodNotAllowed) {
			return route, err
		}
	}

	// Precedence (deterministic): exact → longest prefix → glob → regex.
	// Within each tier, higher Specificity (and PatternRank for glob/regex) wins.
	// An exact path entry short-circuits (no fall-through), matching prior behavior.
	if candidates, ok := r.exact[path]; ok {
		return tryRoutes(candidates, req, host, query)
	}

	var prefixHits []*config.RouteRuntime
	for _, route := range r.prefixes {
		if pathMatchesPrefix(path, route.PathPrefix) {
			prefixHits = append(prefixHits, route)
		}
	}
	if route, err := tryRoutes(prefixHits, req, host, query); err == nil || errors.Is(err, ErrMethodNotAllowed) {
		return route, err
	}

	var globHits []*config.RouteRuntime
	for _, route := range r.globs {
		if route.PathGlobRe.MatchString(path) {
			globHits = append(globHits, route)
		}
	}
	if route, err := tryRoutes(globHits, req, host, query); err == nil || errors.Is(err, ErrMethodNotAllowed) {
		return route, err
	}

	var regexHits []*config.RouteRuntime
	for _, route := range r.regexes {
		if route.PathRegexRe.MatchString(path) {
			regexHits = append(regexHits, route)
		}
	}
	return tryRoutes(regexHits, req, host, query)
}
