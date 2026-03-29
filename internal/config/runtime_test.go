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
