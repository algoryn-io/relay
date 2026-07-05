package config

import (
	"fmt"
	"net/textproto"
	"regexp"
	"strings"
	"time"
)

type RuntimeConfig struct {
	Routes     map[string]RouteRuntime
	Backends   map[string]BackendRuntime
	Middleware map[string]MiddlewareRuntime
}

// CompiledRewrite is a pre-compiled RewriteRule ready to use at request time.
type CompiledRewrite struct {
	Re          *regexp.Regexp
	Replacement string
}

// NewCompiledRewrite compiles pattern and returns a CompiledRewrite ready for
// use at request time. Returns an error if pattern is not valid RE2 syntax.
func NewCompiledRewrite(pattern, replacement string) (*CompiledRewrite, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("compile rewrite pattern: %w", err)
	}
	return &CompiledRewrite{Re: re, Replacement: replacement}, nil
}

// Apply returns the result of applying the rewrite to path.
// If the pattern does not match, the original path is returned unchanged.
func (cr *CompiledRewrite) Apply(path string) string {
	return cr.Re.ReplaceAllString(path, cr.Replacement)
}

type RouteRuntime struct {
	Name              string
	Path              string
	PathPrefix        string
	StripPrefix       string
	Timeout           time.Duration
	MaxBodyBytes      int64
	Rewrite           *CompiledRewrite  // nil when not configured
	AddRequestHeaders map[string]string // nil when not configured
	Methods           []string
	MethodSet         map[string]struct{}
	// HostSet holds the normalized (lowercased) hosts this route is bound to.
	// Empty/nil means the route matches any host.
	HostSet map[string]struct{}
	// HeaderMatch requires each request header (canonicalized name) to equal the
	// given value. Empty/nil means no header constraint.
	HeaderMatch map[string]string
	// QueryMatch requires each query parameter to equal the given value.
	// Empty/nil means no query constraint.
	QueryMatch map[string]string
	// Specificity ranks how constrained the route is (host + header + query
	// predicates). The router prefers higher-specificity routes so a narrow
	// host/header override wins over a catch-all sharing the same path.
	Specificity    int
	Backend        BackendRuntime
	BackendName    string
	Middleware     []MiddlewareRuntime
	MiddlewareRefs []string
}

type BackendRuntime struct {
	Name           string
	Protocol       string
	Strategy       string
	HealthCheck    HealthCheckConfig
	CircuitBreaker CircuitBreakerConfig
	Retry          RetryConfig
	TLS            BackendTLSConfig
	Bulkhead       BulkheadConfig
	Instances      []InstanceRuntime
}

// IsH2C reports whether the backend is reached over cleartext HTTP/2.
func (b BackendRuntime) IsH2C() bool {
	return strings.EqualFold(strings.TrimSpace(b.Protocol), "h2c")
}

type InstanceRuntime struct {
	URL    string
	Weight int // effective weight >= 1; 0 in config is normalised to 1
}

type MiddlewareRuntime struct {
	Name   string
	Type   string
	Config MiddlewareSettingsConfig
}

func BuildRuntime(c *Config) (*RuntimeConfig, error) {
	if c == nil {
		return nil, errNilConfig
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}

	rt := &RuntimeConfig{
		Routes:     make(map[string]RouteRuntime, len(c.Routes)),
		Backends:   make(map[string]BackendRuntime, len(c.Backends)),
		Middleware: make(map[string]MiddlewareRuntime, len(c.Middleware)),
	}

	for _, backend := range c.Backends {
		instances := make([]InstanceRuntime, 0, len(backend.Instances))
		for _, instance := range backend.Instances {
			w := instance.Weight
			if w <= 0 {
				w = 1
			}
			instances = append(instances, InstanceRuntime{URL: instance.URL, Weight: w})
		}

		rt.Backends[backend.Name] = BackendRuntime{
			Name:           backend.Name,
			Protocol:       backend.Protocol,
			Strategy:       backend.Strategy,
			HealthCheck:    backend.HealthCheck,
			CircuitBreaker: backend.CircuitBreaker,
			Retry:          backend.Retry,
			TLS:            backend.TLS,
			Bulkhead:       backend.Bulkhead,
			Instances:      instances,
		}
	}

	for _, middleware := range c.Middleware {
		rt.Middleware[middleware.Name] = MiddlewareRuntime{
			Name:   middleware.Name,
			Type:   middleware.Type,
			Config: middleware.Config,
		}
	}

	for _, route := range c.Routes {
		methods := make([]string, 0, len(route.Match.Methods))
		methodSet := make(map[string]struct{}, len(route.Match.Methods))
		for _, method := range route.Match.Methods {
			normalized := strings.ToUpper(strings.TrimSpace(method))
			methods = append(methods, normalized)
			methodSet[normalized] = struct{}{}
		}

		middleware := make([]MiddlewareRuntime, 0, len(route.Middleware))
		for _, name := range route.Middleware {
			middleware = append(middleware, rt.Middleware[name])
		}

		path := strings.TrimSpace(route.Match.Path)
		pathPrefix := strings.TrimSpace(route.Match.PathPrefix)

		var hostSet map[string]struct{}
		if len(route.Match.Hosts) > 0 {
			hostSet = make(map[string]struct{}, len(route.Match.Hosts))
			for _, h := range route.Match.Hosts {
				h = strings.ToLower(strings.TrimSpace(h))
				if h != "" {
					hostSet[h] = struct{}{}
				}
			}
		}

		headerMatch := normalizeHeaderMatch(route.Match.Headers)
		queryMatch := normalizeStringMap(route.Match.Query)

		specificity := 0
		if len(hostSet) > 0 {
			specificity += 100
		}
		specificity += len(headerMatch) + len(queryMatch)

		var compiled *CompiledRewrite
		if strings.TrimSpace(route.Rewrite.Pattern) != "" {
			re, err := regexp.Compile(route.Rewrite.Pattern)
			if err != nil {
				// Validation already checked this; guard against any gap.
				return nil, fmt.Errorf("route %q: compile rewrite pattern: %w", route.Name, err)
			}
			compiled = &CompiledRewrite{Re: re, Replacement: route.Rewrite.Replacement}
		}

		rt.Routes[route.Name] = RouteRuntime{
			Name:              route.Name,
			Path:              path,
			PathPrefix:        pathPrefix,
			StripPrefix:       strings.TrimSpace(route.StripPrefix),
			Timeout:           route.Timeout,
			MaxBodyBytes:      route.MaxBodyBytes,
			Rewrite:           compiled,
			AddRequestHeaders: route.AddRequestHeaders,
			Methods:           methods,
			MethodSet:         methodSet,
			HostSet:           hostSet,
			HeaderMatch:       headerMatch,
			QueryMatch:        queryMatch,
			Specificity:       specificity,
			Backend:           rt.Backends[route.Backend],
			BackendName:       route.Backend,
			Middleware:        middleware,
			MiddlewareRefs:    append([]string(nil), route.Middleware...),
		}
	}

	return rt, nil
}

// normalizeHeaderMatch canonicalizes header names (so lookups match
// http.Header.Get) and drops blank keys. Returns nil when nothing remains.
func normalizeHeaderMatch(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		out[textproto.CanonicalMIMEHeaderKey(k)] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// normalizeStringMap trims keys and drops blank ones. Returns nil when empty.
func normalizeStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
