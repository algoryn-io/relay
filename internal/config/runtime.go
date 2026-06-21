package config

import (
	"fmt"
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
	Backend           BackendRuntime
	BackendName       string
	Middleware        []MiddlewareRuntime
	MiddlewareRefs    []string
}

type BackendRuntime struct {
	Name           string
	Strategy       string
	HealthCheck    HealthCheckConfig
	CircuitBreaker CircuitBreakerConfig
	Retry          RetryConfig
	TLS            BackendTLSConfig
	Bulkhead       BulkheadConfig
	Instances      []InstanceRuntime
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
			Backend:           rt.Backends[route.Backend],
			BackendName:       route.Backend,
			Middleware:        middleware,
			MiddlewareRefs:    append([]string(nil), route.Middleware...),
		}
	}

	return rt, nil
}
