package config

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

var (
	validBackendStrategies = map[string]struct{}{
		"round_robin":       {},
		"least_connections": {},
		"weighted_random":   {},
	}
	validMiddlewareTypes = map[string]struct{}{
		"jwt":        {},
		"rate_limit": {},
		"body_limit": {},
		"ip_filter":  {},
		"cors":       {},
		"header":     {},
		"api_key":    {},
	}
)

func validateConfig(c *Config) error {
	var errs ValidationErrors

	validateListener(c.Listener, &errs)

	backendNames := validateBackends(c.Backends, &errs)
	middlewareNames := validateMiddlewares(c.Middleware, &errs)
	validateRoutes(c.Routes, backendNames, middlewareNames, &errs)

	validateObservability(c.Observability, &errs)
	validateStorage(c.Storage, &errs)
	validateReload(c.Reload, &errs)

	return errs.Err()
}

func validateListener(listener ListenerConfig, errs *ValidationErrors) {
	if listener.HTTP.Port <= 0 && listener.HTTPS.Port <= 0 {
		errs.Addf("listener: at least one of listener.http.port or listener.https.port must be greater than 0")
	}
	if listener.HTTP.Port < 0 {
		errs.Addf("listener.http.port: must be greater than 0")
	}
	if listener.HTTPS.Port < 0 {
		errs.Addf("listener.https.port: must be greater than 0")
	}

	if listener.HTTPS.Port > 0 {
		validateTLS("listener.https.tls", listener.HTTPS.TLS, errs)
	}

	validatePositiveDuration("listener.timeouts.read", listener.Timeouts.Read, errs, false)
	validatePositiveDuration("listener.timeouts.write", listener.Timeouts.Write, errs, false)
	validatePositiveDuration("listener.timeouts.idle", listener.Timeouts.Idle, errs, false)
	validateIPFilterEntries("listener.trusted_proxies", listener.TrustedProxies, errs)
	validateIPFilterEntries("listener.admin.allowed_cidrs", listener.Admin.AllowedCIDRs, errs)
}

func validateTLS(prefix string, tls TLSConfig, errs *ValidationErrors) {
	mode := strings.ToLower(strings.TrimSpace(tls.Mode))
	if mode == "" {
		mode = "manual"
	}
	switch mode {
	case "manual":
		if strings.TrimSpace(tls.CertFile) == "" {
			errs.Addf("%s.cert_file: required for mode manual", prefix)
		}
		if strings.TrimSpace(tls.KeyFile) == "" {
			errs.Addf("%s.key_file: required for mode manual", prefix)
		}
	case "auto":
		if len(tls.Domains) == 0 {
			errs.Addf("%s.domains: at least one domain is required for mode auto", prefix)
		}
		for i, d := range tls.Domains {
			if strings.TrimSpace(d) == "" {
				errs.Addf("%s.domains[%d]: must not be empty", prefix, i)
			}
		}
	default:
		errs.Addf("%s.mode: must be one of manual, auto", prefix)
	}
}

func validateRoutes(routes []RouteConfig, backendNames, middlewareNames map[string]struct{}, errs *ValidationErrors) {
	seen := make(map[string]struct{}, len(routes))

	for i, route := range routes {
		prefix := fmt.Sprintf("routes[%d]", i)
		if route.Name == "" {
			errs.Addf("%s.name: required", prefix)
		} else {
			if _, ok := seen[route.Name]; ok {
				errs.Addf("%s.name: duplicate value %q", prefix, route.Name)
			}
			seen[route.Name] = struct{}{}
		}

		path := strings.TrimSpace(route.Match.Path)
		pathPrefix := strings.TrimSpace(route.Match.PathPrefix)
		switch {
		case path == "" && pathPrefix == "":
			errs.Addf("%s.match: exactly one of path or path_prefix is required", prefix)
		case path != "" && pathPrefix != "":
			errs.Addf("%s.match: path and path_prefix are mutually exclusive", prefix)
		}
		if len(route.Match.Methods) == 0 {
			errs.Addf("%s.match.methods: must not be empty", prefix)
		}
		for j, method := range route.Match.Methods {
			if strings.TrimSpace(method) == "" {
				errs.Addf("%s.match.methods[%d]: must not be empty", prefix, j)
			}
		}

		if route.Timeout < 0 {
			errs.Addf("%s.timeout: must be >= 0", prefix)
		}
		if route.StripPrefix != "" && !strings.HasPrefix(route.StripPrefix, "/") {
			errs.Addf("%s.strip_prefix: must start with /", prefix)
		}

		if route.Backend == "" {
			errs.Addf("%s.backend: required", prefix)
		} else if _, ok := backendNames[route.Backend]; !ok {
			errs.Addf("%s.backend: unknown backend %q", prefix, route.Backend)
		}

		for j, name := range route.Middleware {
			if _, ok := middlewareNames[name]; !ok {
				errs.Addf("%s.middleware[%d]: unknown middleware %q", prefix, j, name)
			}
		}
	}
}

func validateBackends(backends []BackendConfig, errs *ValidationErrors) map[string]struct{} {
	seen := make(map[string]struct{}, len(backends))

	for i, backend := range backends {
		prefix := fmt.Sprintf("backends[%d]", i)

		if backend.Name == "" {
			errs.Addf("%s.name: required", prefix)
		} else {
			if _, ok := seen[backend.Name]; ok {
				errs.Addf("%s.name: duplicate value %q", prefix, backend.Name)
			}
			seen[backend.Name] = struct{}{}
		}

		if _, ok := validBackendStrategies[backend.Strategy]; !ok {
			errs.Addf("%s.strategy: must be one of round_robin, least_connections", prefix)
		}

		if len(backend.Instances) == 0 {
			errs.Addf("%s.instances: must contain at least one instance", prefix)
		}

		validatePositiveDuration(prefix+".health_check.interval", backend.HealthCheck.Interval, errs, true)
		validatePositiveDuration(prefix+".health_check.timeout", backend.HealthCheck.Timeout, errs, true)

		cb := backend.CircuitBreaker
		if cb.Threshold < 0 {
			errs.Addf("%s.circuit_breaker.threshold: must be >= 0", prefix)
		}
		if cb.Threshold > 0 && cb.Timeout < 0 {
			errs.Addf("%s.circuit_breaker.timeout: must be >= 0", prefix)
		}

		validateRetry(prefix+".retry", backend.Retry, errs)
		validateBackendTLS(prefix+".tls", backend.TLS, errs)
		if backend.Bulkhead.MaxConcurrent < 0 {
			errs.Addf("%s.bulkhead.max_concurrent: must be >= 0", prefix)
		}

		for j, instance := range backend.Instances {
			if instance.URL == "" {
				errs.Addf("%s.instances[%d].url: required", prefix, j)
				continue
			}
			parsed, err := url.Parse(instance.URL)
			if err != nil || parsed.Scheme == "" || parsed.Host == "" {
				errs.Addf("%s.instances[%d].url: invalid URL %q", prefix, j, instance.URL)
				continue
			}
			if parsed.Scheme != "http" && parsed.Scheme != "https" {
				errs.Addf("%s.instances[%d].url: scheme must be http or https", prefix, j)
			}
			if instance.Weight < 0 {
				errs.Addf("%s.instances[%d].weight: must be >= 0", prefix, j)
			}
		}
	}

	return seen
}

func validateMiddlewares(middlewares []MiddlewareConfig, errs *ValidationErrors) map[string]struct{} {
	seen := make(map[string]struct{}, len(middlewares))

	for i, middleware := range middlewares {
		prefix := fmt.Sprintf("middleware[%d]", i)

		if middleware.Name == "" {
			errs.Addf("%s.name: required", prefix)
		} else {
			if _, ok := seen[middleware.Name]; ok {
				errs.Addf("%s.name: duplicate value %q", prefix, middleware.Name)
			}
			seen[middleware.Name] = struct{}{}
		}

		if _, ok := validMiddlewareTypes[middleware.Type]; !ok {
			errs.Addf("%s.type: must be one of jwt, rate_limit, body_limit, ip_filter, cors, header, api_key", prefix)
		}

		if middleware.Type == "jwt" {
			validateJWTMiddleware(prefix+".config", middleware.Config, errs)
		}
		if middleware.Type == "rate_limit" {
			if middleware.Config.Strategy != "sliding_window" {
				errs.Addf("%s.config.strategy: only sliding_window is supported in this phase", prefix)
			}
			if middleware.Config.Limit <= 0 {
				errs.Addf("%s.config.limit: must be greater than 0", prefix)
			}
			if middleware.Config.Window <= 0 {
				errs.Addf("%s.config.window: must be greater than 0", prefix)
			}
			switch middleware.Config.By {
			case "ip", "route", "api_key":
			default:
				errs.Addf("%s.config.by: must be one of ip, route, api_key", prefix)
			}
			store := strings.ToLower(strings.TrimSpace(middleware.Config.RateLimitStore))
			switch store {
			case "", "memory", "redis":
			default:
				errs.Addf("%s.config.store: must be one of memory, redis", prefix)
			}
			if store == "redis" {
				hasURL := strings.TrimSpace(middleware.Config.RedisURL) != ""
				hasURLEnv := strings.TrimSpace(middleware.Config.RedisURLEnv) != ""
				if !hasURL && !hasURLEnv {
					errs.Addf("%s.config: redis_url or redis_url_env is required when store is redis", prefix)
				}
			}
		}
		if middleware.Type == "cors" {
			if len(middleware.Config.AllowedOrigins) == 0 {
				errs.Addf("%s.config.allowed_origins: must not be empty", prefix)
			}
			if len(middleware.Config.AllowedMethods) == 0 {
				errs.Addf("%s.config.allowed_methods: must not be empty", prefix)
			}
		}
		if middleware.Type == "body_limit" {
			if middleware.Config.MaxBytes <= 0 {
				errs.Addf("%s.config.max_bytes: must be greater than 0", prefix)
			}
		}
		if middleware.Type == "ip_filter" {
			if len(middleware.Config.Allow) == 0 && len(middleware.Config.Deny) == 0 {
				errs.Addf("%s.config: at least one of allow or deny must be provided", prefix)
			}
			validateIPFilterEntries(prefix+".config.allow", middleware.Config.Allow, errs)
			validateIPFilterEntries(prefix+".config.deny", middleware.Config.Deny, errs)
		}
		if middleware.Type == "header" {
			if len(middleware.Config.RequestSet) == 0 &&
				len(middleware.Config.RequestDel) == 0 &&
				len(middleware.Config.ResponseSet) == 0 &&
				len(middleware.Config.ResponseDel) == 0 {
				errs.Addf("%s.config: at least one of request_set, request_del, response_set, response_del must be provided", prefix)
			}
		}
		if middleware.Type == "api_key" {
			validateAPIKeyMiddleware(prefix+".config", middleware.Config, errs)
		}
	}

	return seen
}

func validateBackendTLS(prefix string, cfg BackendTLSConfig, errs *ValidationErrors) {
	hasCert := strings.TrimSpace(cfg.CertFile) != ""
	hasKey := strings.TrimSpace(cfg.KeyFile) != ""
	if hasCert && !hasKey {
		errs.Addf("%s.key_file: required when cert_file is set", prefix)
	}
	if hasKey && !hasCert {
		errs.Addf("%s.cert_file: required when key_file is set", prefix)
	}
}

func validateAPIKeyMiddleware(prefix string, cfg MiddlewareSettingsConfig, errs *ValidationErrors) {
	hasEnv := strings.TrimSpace(cfg.KeysEnv) != ""
	hasFile := strings.TrimSpace(cfg.KeysFile) != ""
	if !hasEnv && !hasFile {
		errs.Addf("%s: at least one of keys_env or keys_file is required", prefix)
	}
}

func validateIPFilterEntries(field string, entries []string, errs *ValidationErrors) {
	for i, entry := range entries {
		value := strings.TrimSpace(entry)
		if value == "" {
			errs.Addf("%s[%d]: must not be empty", field, i)
			continue
		}

		if ip := net.ParseIP(value); ip != nil {
			continue
		}
		if _, _, err := net.ParseCIDR(value); err == nil {
			continue
		}
		errs.Addf("%s[%d]: must be a valid IP or CIDR", field, i)
	}
}

func validateJWTMiddleware(prefix string, cfg MiddlewareSettingsConfig, errs *ValidationErrors) {
	alg := strings.ToLower(strings.TrimSpace(cfg.Algorithm))
	if alg == "" {
		alg = "hs256"
	}

	switch alg {
	case "hs256":
		if strings.TrimSpace(cfg.SecretEnv) == "" {
			errs.Addf("%s.secret_env: required for algorithm hs256", prefix)
		}
	case "rs256":
		hasFile := strings.TrimSpace(cfg.PublicKeyFile) != ""
		hasJWKS := strings.TrimSpace(cfg.JWKSUrl) != ""
		switch {
		case hasFile && hasJWKS:
			errs.Addf("%s: public_key_file and jwks_url are mutually exclusive", prefix)
		case !hasFile && !hasJWKS:
			errs.Addf("%s: one of public_key_file or jwks_url is required for algorithm rs256", prefix)
		case hasJWKS && cfg.JWKSCacheTTL < 0:
			errs.Addf("%s.jwks_cache_ttl: must be >= 0", prefix)
		}
	default:
		errs.Addf("%s.algorithm: must be one of hs256, rs256", prefix)
	}

	validateJWTClaimsToHeaders(prefix, cfg.ClaimsToHeaders, errs)
}

func validateJWTClaimsToHeaders(field string, m map[string]string, errs *ValidationErrors) {
	if len(m) == 0 {
		return
	}

	seenDest := make(map[string]struct{}, len(m))
	for claim, dest := range m {
		claim = strings.TrimSpace(claim)
		dest = strings.TrimSpace(dest)
		if claim == "" {
			errs.Addf("%s.claims_to_headers: claim name must not be empty", field)
		}
		if dest == "" {
			errs.Addf("%s.claims_to_headers: header name for claim %q must not be empty", field, claim)
		}
		if _, ok := seenDest[dest]; ok {
			errs.Addf("%s.claims_to_headers: duplicate destination header %q", field, dest)
		} else {
			seenDest[dest] = struct{}{}
		}
	}
}

func validateObservability(observability ObservabilityConfig, errs *ValidationErrors) {
	if observability.Dashboard.Enabled && observability.Dashboard.Port <= 0 {
		errs.Addf("observability.dashboard.port: must be greater than 0")
	}
	if observability.Logs.File != "" && strings.TrimSpace(observability.Logs.File) == "" {
		errs.Addf("observability.logs.file: must not be blank")
	}
	if observability.Logs.MaxSizeMB < 0 {
		errs.Addf("observability.logs.max_size_mb: must be >= 0")
	}
	validatePositiveDuration("observability.metrics.flush_interval", observability.Metrics.FlushInterval, errs, false)
	validateFabric(observability.Fabric, errs)
	validateTracing(observability.Tracing, errs)
}

func validateTracing(t TracingConfig, errs *ValidationErrors) {
	if !t.Enabled {
		return
	}
	exp := strings.ToLower(strings.TrimSpace(t.Exporter))
	switch exp {
	case "otlp_grpc", "otlp_http", "stdout", "":
	default:
		errs.Addf("observability.tracing.exporter: must be one of otlp_grpc, otlp_http, stdout")
	}
	if t.SampleRate < 0 || t.SampleRate > 1 {
		errs.Addf("observability.tracing.sample_rate: must be between 0.0 and 1.0")
	}
}

var validRetryConditions = map[string]struct{}{
	"5xx":           {},
	"network_error": {},
}

func validateRetry(prefix string, r RetryConfig, errs *ValidationErrors) {
	if r.Attempts <= 1 {
		return
	}
	if r.BackoffInit < 0 {
		errs.Addf("%s.backoff_init: must be >= 0", prefix)
	}
	if r.BackoffMax < 0 {
		errs.Addf("%s.backoff_max: must be >= 0", prefix)
	}
	if r.BackoffMax > 0 && r.BackoffInit > 0 && r.BackoffMax < r.BackoffInit {
		errs.Addf("%s.backoff_max: must be >= backoff_init", prefix)
	}
	for i, cond := range r.On {
		if _, ok := validRetryConditions[strings.ToLower(cond)]; !ok {
			errs.Addf("%s.on[%d]: must be one of 5xx, network_error", prefix, i)
		}
	}
}

func validateFabric(f FabricConfig, errs *ValidationErrors) {
	if !f.Enabled {
		return
	}
	if strings.TrimSpace(f.ServiceName) == "" {
		errs.Addf("observability.fabric.service_name: required when fabric.enabled is true")
	}
	if f.QueueSize < 0 {
		errs.Addf("observability.fabric.queue_size: must be >= 0")
	}
}

func validateStorage(_ StorageConfig, _ *ValidationErrors) {
	// storage is optional; leave path empty to disable
}

func validateReload(reload ReloadConfig, errs *ValidationErrors) {
	if !reload.Watch {
		return
	}
	if reload.Debounce <= 0 {
		errs.Addf("reload.debounce: must be > 0 when reload.watch is enabled")
	}
}

func validatePositiveDuration(field string, value time.Duration, errs *ValidationErrors, allowZero bool) {
	if value < 0 {
		errs.Addf("%s: must be greater than 0", field)
		return
	}
	if !allowZero && value == 0 {
		errs.Addf("%s: must be greater than 0", field)
	}
}
