package config

import "strings"

type RuntimeConfig struct {
	Routes     map[string]RouteRuntime
	Backends   map[string]BackendRuntime
	Middleware map[string]MiddlewareRuntime
}

type RouteRuntime struct {
	Name           string
	Path           string
	PathPrefix     string
	Methods        []string
	MethodSet      map[string]struct{}
	Backend        BackendRuntime
	BackendName    string
	Middleware     []MiddlewareRuntime
	MiddlewareRefs []string
}

type BackendRuntime struct {
	Name        string
	Strategy    string
	HealthCheck HealthCheckConfig
	Instances   []InstanceRuntime
}

type InstanceRuntime struct {
	URL string
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
			instances = append(instances, InstanceRuntime{URL: instance.URL})
		}

		rt.Backends[backend.Name] = BackendRuntime{
			Name:        backend.Name,
			Strategy:    backend.Strategy,
			HealthCheck: backend.HealthCheck,
			Instances:   instances,
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

		rt.Routes[route.Name] = RouteRuntime{
			Name:           route.Name,
			Path:           path,
			PathPrefix:     pathPrefix,
			Methods:        methods,
			MethodSet:      methodSet,
			Backend:        rt.Backends[route.Backend],
			BackendName:    route.Backend,
			Middleware:     middleware,
			MiddlewareRefs: append([]string(nil), route.Middleware...),
		}
	}

	return rt, nil
}
