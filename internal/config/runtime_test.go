package config

import "testing"

func TestBuildRuntime(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.Routes[0].Match.Methods = []string{"get", "post"}

	rt, err := BuildRuntime(cfg)
	if err != nil {
		t.Fatalf("BuildRuntime() error = %v", err)
	}

	route := rt.Routes["orders-route"]
	if _, ok := route.MethodSet["GET"]; !ok {
		t.Fatal("GET method not normalized into runtime method set")
	}
	if _, ok := route.MethodSet["POST"]; !ok {
		t.Fatal("POST method not normalized into runtime method set")
	}
	if route.Backend.Name != "orders-backend" {
		t.Fatalf("runtime backend = %q, want orders-backend", route.Backend.Name)
	}
	if len(route.Middleware) != 1 || route.Middleware[0].Name != "jwt-auth" {
		t.Fatalf("runtime middleware = %+v, want jwt-auth", route.Middleware)
	}
}

func TestBuildRuntimeNormalizesMatchPredicates(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.Routes[0].Match.Hosts = []string{"  API.Example.COM  "}
	cfg.Routes[0].Match.Headers = map[string]string{"x-canary": "true"}
	cfg.Routes[0].Match.Query = map[string]string{"version": "2"}

	rt, err := BuildRuntime(cfg)
	if err != nil {
		t.Fatalf("BuildRuntime() error = %v", err)
	}

	route := rt.Routes["orders-route"]
	if _, ok := route.HostSet["api.example.com"]; !ok {
		t.Fatalf("host not normalized to lowercase/trimmed: %+v", route.HostSet)
	}
	if got := route.HeaderMatch["X-Canary"]; got != "true" {
		t.Fatalf("header name not canonicalized: %+v", route.HeaderMatch)
	}
	if got := route.QueryMatch["version"]; got != "2" {
		t.Fatalf("query match = %+v", route.QueryMatch)
	}
	// host (100) + 1 header + 1 query = 102.
	if route.Specificity != 102 {
		t.Fatalf("specificity = %d, want 102", route.Specificity)
	}
}

func TestBuildRuntimeDropsDangerousOptionAcknowledgements(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.Middleware = []MiddlewareConfig{
		{
			Name: "api-key",
			Type: "api_key",
			Config: MiddlewareSettingsConfig{
				KeyQuery:                    "api_key",
				KeysEnv:                     "RELAY_API_KEYS",
				AcknowledgeAPIKeyInQuery:    true,
				AcknowledgeExtAuthzFailOpen: true,
			},
		},
	}
	cfg.Routes[0].Middleware = []string{"api-key"}

	rt, err := BuildRuntime(cfg)
	if err != nil {
		t.Fatalf("BuildRuntime() error = %v", err)
	}
	settings := rt.Middleware["api-key"].Config
	if settings.AcknowledgeAPIKeyInQuery || settings.AcknowledgeExtAuthzFailOpen {
		t.Fatalf("validation-only acknowledgements leaked into runtime: %+v", settings)
	}
	if settings.KeyQuery != "api_key" {
		t.Fatalf("runtime key_query = %q, want api_key", settings.KeyQuery)
	}
}
