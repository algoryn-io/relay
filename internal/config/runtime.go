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
	Name                    string
	Path                    string
	PathPrefix              string
	StripPrefix             string
	Timeout                 time.Duration
	MaxBodyBytes            int64
	Rewrite                 *CompiledRewrite  // nil when not configured
	AddRequestHeaders       map[string]string // nil when not configured
	PropagateClientIdentity ClientIdentityPropagationConfig
	Methods                 []string
	MethodSet               map[string]struct{}
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
	Specificity int
	Backend     BackendRuntime
	BackendName string
	// FailoverBackends are secondary backends tried after BackendName.
	FailoverBackends []string
	Middleware       []MiddlewareRuntime
	MiddlewareRefs   []string
}

type BackendRuntime struct {
	Name                    string
	Protocol                string
	Strategy                string
	HealthCheck             HealthCheckConfig
	OutlierDetection        OutlierDetectionConfig
	CircuitBreaker          CircuitBreakerConfig
	Retry                   RetryConfig
	TLS                     BackendTLSConfig
	PropagateClientIdentity ClientIdentityPropagationConfig
	Bulkhead                BulkheadConfig
	// Discovery holds DNS discovery settings when instances are dynamic.
	// Nil means static Instances.
	Discovery *DNSDiscoveryConfig
	Instances []InstanceRuntime
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

		var discovery *DNSDiscoveryConfig
		if backend.Discovery.DNS != nil {
			dns := *backend.Discovery.DNS
			if strings.TrimSpace(dns.RecordType) == "" {
				dns.RecordType = "A"
			}
			if strings.TrimSpace(dns.Scheme) == "" {
				dns.Scheme = "http"
			}
			if dns.RefreshInterval <= 0 {
				dns.RefreshInterval = 30 * time.Second
			}
			if dns.TTLMin <= 0 {
				dns.TTLMin = time.Second
			}
			if dns.Weight <= 0 {
				dns.Weight = 1
			}
			discovery = &dns
		}

		rt.Backends[backend.Name] = BackendRuntime{
			Name:                    backend.Name,
			Protocol:                backend.Protocol,
			Strategy:                backend.Strategy,
			HealthCheck:             backend.HealthCheck,
			OutlierDetection:        backend.OutlierDetection,
			CircuitBreaker:          backend.CircuitBreaker,
			Retry:                   backend.Retry,
			TLS:                     backend.TLS,
			PropagateClientIdentity: backend.PropagateClientIdentity,
			Bulkhead:                backend.Bulkhead,
			Discovery:               discovery,
			Instances:               instances,
		}
	}

	for _, middleware := range c.Middleware {
		runtimeSettings := middleware.Config
		// Dangerous-option acknowledgements are validation-only. Do not carry
		// them into runtime state or let them influence middleware behavior.
		runtimeSettings.AcknowledgeAPIKeyInQuery = false
		runtimeSettings.AcknowledgeExtAuthzFailOpen = false
		rt.Middleware[middleware.Name] = MiddlewareRuntime{
			Name:   middleware.Name,
			Type:   middleware.Type,
			Config: runtimeSettings,
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

		identityPolicy := rt.Backends[route.Backend].PropagateClientIdentity
		if route.PropagateClientIdentity != nil {
			identityPolicy = *route.PropagateClientIdentity
		}

		failover := normalizeFailoverBackends(route.Failover)

		rt.Routes[route.Name] = RouteRuntime{
			Name:                    route.Name,
			Path:                    path,
			PathPrefix:              pathPrefix,
			StripPrefix:             strings.TrimSpace(route.StripPrefix),
			Timeout:                 route.Timeout,
			MaxBodyBytes:            route.MaxBodyBytes,
			Rewrite:                 compiled,
			AddRequestHeaders:       route.AddRequestHeaders,
			PropagateClientIdentity: identityPolicy,
			Methods:                 methods,
			MethodSet:               methodSet,
			HostSet:                 hostSet,
			HeaderMatch:             headerMatch,
			QueryMatch:              queryMatch,
			Specificity:             specificity,
			Backend:                 rt.Backends[route.Backend],
			BackendName:             route.Backend,
			FailoverBackends:        failover,
			Middleware:              middleware,
			MiddlewareRefs:          append([]string(nil), route.Middleware...),
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

// normalizeFailoverBackends returns the ordered secondary backend list from
// either failover.secondary or failover.backends.
func normalizeFailoverBackends(cfg RouteFailoverConfig) []string {
	if sec := strings.TrimSpace(cfg.Secondary); sec != "" {
		return []string{sec}
	}
	if len(cfg.Backends) == 0 {
		return nil
	}
	out := make([]string, 0, len(cfg.Backends))
	for _, name := range cfg.Backends {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		out = append(out, name)
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
