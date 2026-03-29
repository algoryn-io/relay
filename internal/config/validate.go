package config

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

var (
	validBackendStrategies = map[string]struct{}{
		"round_robin":       {},
		"least_connections": {},
	}
	validMiddlewareTypes = map[string]struct{}{
		"jwt":        {},
		"rate_limit": {},
		"ip_filter":  {},
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

	validatePositiveDuration("listener.timeouts.read", listener.Timeouts.Read, errs, false)
	validatePositiveDuration("listener.timeouts.write", listener.Timeouts.Write, errs, false)
	validatePositiveDuration("listener.timeouts.idle", listener.Timeouts.Idle, errs, false)
	validatePositiveDuration("listener.timeouts.header", listener.Timeouts.Header, errs, true)
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

		if route.Match.Path == "" {
			errs.Addf("%s.match.path: required", prefix)
		}
		if len(route.Match.Methods) == 0 {
			errs.Addf("%s.match.methods: must not be empty", prefix)
		}
		for j, method := range route.Match.Methods {
			if strings.TrimSpace(method) == "" {
				errs.Addf("%s.match.methods[%d]: must not be empty", prefix, j)
			}
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

		for j, instance := range backend.Instances {
			if instance.URL == "" {
				errs.Addf("%s.instances[%d].url: required", prefix, j)
				continue
			}
			parsed, err := url.Parse(instance.URL)
			if err != nil || parsed.Scheme == "" || parsed.Host == "" {
				errs.Addf("%s.instances[%d].url: invalid URL %q", prefix, j, instance.URL)
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
			errs.Addf("%s.type: must be one of jwt, rate_limit, ip_filter", prefix)
		}

		if middleware.Type == "jwt" && strings.TrimSpace(middleware.Config.SecretEnv) == "" && strings.TrimSpace(middleware.Config.Secret) == "" {
			errs.Addf("%s.config.secret_env: required for jwt middleware", prefix)
		}
	}

	return seen
}

func validateObservability(observability ObservabilityConfig, errs *ValidationErrors) {
	if observability.Dashboard.Enabled && observability.Dashboard.Port <= 0 {
		errs.Addf("observability.dashboard.port: must be greater than 0")
	}
	validatePositiveDuration("observability.metrics.flush_interval", observability.Metrics.FlushInterval, errs, false)
}

func validateStorage(storage StorageConfig, errs *ValidationErrors) {
	if strings.TrimSpace(storage.Path) == "" {
		errs.Addf("storage.path: required")
	}
}

func validateReload(reload ReloadConfig, errs *ValidationErrors) {
	validatePositiveDuration("reload.debounce", reload.Debounce, errs, false)
}

func validatePositiveDuration(field string, value time.Duration, errs *ValidationErrors, allowZero bool) {
	if value < 0 {
		errs.Addf("%s: must be greater than 0", field)
		return
	}
	if !allowZero && value == 0 {
		errs.Addf("%s: must be greater than 0", field)
		return
	}

func Validate(c *Config) error {
	_ = c
	// TODO: implement top-level config validation for listener, routes, and backends.
	return nil
}

func validateRoutes(routes []RouteConfig) error {
	_ = routes
	// TODO: implement route definition validation including unique IDs and match clauses.
	return nil
}

func validateBackends(backends []BackendConfig) error {
	_ = backends
	// TODO: implement backend validation including strategy and instance URL checks.
	return nil
}

func validateMiddlewares(middlewares []MiddlewareConfig) error {
	_ = middlewares
	// TODO: implement middleware validation including type-specific required fields.
	return nil
}
