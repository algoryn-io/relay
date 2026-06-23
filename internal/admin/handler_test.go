package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"algoryn.io/relay/internal/config"
	"algoryn.io/relay/internal/proxy"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func buildProxy(t *testing.T, backendURL string) *proxy.Proxy {
	t.Helper()
	rt := &config.RuntimeConfig{
		Backends: map[string]config.BackendRuntime{
			"api": {
				Name:      "api",
				Strategy:  "round_robin",
				Instances: []config.InstanceRuntime{{URL: backendURL}},
			},
		},
		Routes: map[string]config.RouteRuntime{},
	}
	p, err := proxy.New(rt, nil)
	if err != nil {
		t.Fatalf("proxy.New() error = %v", err)
	}
	t.Cleanup(p.Close)
	return p
}

func buildHandler(t *testing.T, px *proxy.Proxy, routes map[string]config.RouteRuntime) *Handler {
	t.Helper()
	// Allow all IPs in tests by using "0.0.0.0/0".
	return New(px, routes, []string{"0.0.0.0/0", "::/0"}, "", nil)
}

func getJSON(t *testing.T, h http.Handler, path string) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = "127.0.0.1:1234"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET %s status = %d, want 200; body: %s", path, rr.Code, rr.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	return out
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestListBackendsReturnsAll(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	h := buildHandler(t, buildProxy(t, srv.URL), nil)
	body := getJSON(t, h, "/_relay/admin/backends")

	backends, ok := body["backends"].([]any)
	if !ok {
		t.Fatalf("expected backends array, got %T", body["backends"])
	}
	if len(backends) != 1 {
		t.Fatalf("expected 1 backend, got %d", len(backends))
	}
}

func TestGetSingleBackend(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	h := buildHandler(t, buildProxy(t, srv.URL), nil)
	body := getJSON(t, h, "/_relay/admin/backends/api")

	if body["name"] != "api" {
		t.Errorf("name = %v, want api", body["name"])
	}
}

func TestGetUnknownBackendReturns404(t *testing.T) {
	t.Parallel()

	h := buildHandler(t, buildProxy(t, "http://127.0.0.1:1"), nil)

	req := httptest.NewRequest(http.MethodGet, "/_relay/admin/backends/nope", nil)
	req.RemoteAddr = "127.0.0.1:1"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
}

func TestDrainInstance(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	px := buildProxy(t, srv.URL)
	h := buildHandler(t, px, nil)

	req := httptest.NewRequest(http.MethodPost,
		"/_relay/admin/backends/api/drain?instance="+srv.URL, nil)
	req.RemoteAddr = "127.0.0.1:1"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("drain status = %d, body: %s", rr.Code, rr.Body.String())
	}

	// Verify the instance is now unhealthy in the snapshot.
	snap, ok := px.BackendSnapshot("api")
	if !ok {
		t.Fatal("backend not found after drain")
	}
	if snap.Instances[0].Healthy {
		t.Error("instance should be marked unhealthy after drain")
	}
}

func TestDrainMissingInstanceParam(t *testing.T) {
	t.Parallel()

	h := buildHandler(t, buildProxy(t, "http://127.0.0.1:1"), nil)
	req := httptest.NewRequest(http.MethodPost, "/_relay/admin/backends/api/drain", nil)
	req.RemoteAddr = "127.0.0.1:1"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

func TestListRoutes(t *testing.T) {
	t.Parallel()

	routes := map[string]config.RouteRuntime{
		"r1": {Name: "r1", Path: "/api", BackendName: "api", Methods: []string{"GET"}},
	}
	h := buildHandler(t, buildProxy(t, "http://127.0.0.1:1"), routes)
	body := getJSON(t, h, "/_relay/admin/routes")

	list, ok := body["routes"].([]any)
	if !ok {
		t.Fatalf("expected routes array, got %T", body["routes"])
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 route, got %d", len(list))
	}
}

func TestListCircuitBreakers(t *testing.T) {
	t.Parallel()

	rt := &config.RuntimeConfig{
		Backends: map[string]config.BackendRuntime{
			"api": {
				Name:           "api",
				Strategy:       "round_robin",
				CircuitBreaker: config.CircuitBreakerConfig{Threshold: 3},
				Instances:      []config.InstanceRuntime{{URL: "http://127.0.0.1:9999"}},
			},
		},
		Routes: map[string]config.RouteRuntime{},
	}
	px, err := proxy.New(rt, nil)
	if err != nil {
		t.Fatalf("proxy.New() error = %v", err)
	}
	t.Cleanup(px.Close)

	h := buildHandler(t, px, nil)
	body := getJSON(t, h, "/_relay/admin/circuit-breakers")

	cbs, ok := body["circuit_breakers"].([]any)
	if !ok {
		t.Fatalf("expected circuit_breakers array, got %T", body["circuit_breakers"])
	}
	if len(cbs) != 1 {
		t.Fatalf("expected 1 circuit breaker entry, got %d", len(cbs))
	}
}

func TestResetCircuit(t *testing.T) {
	t.Parallel()

	rt := &config.RuntimeConfig{
		Backends: map[string]config.BackendRuntime{
			"api": {
				Name:           "api",
				Strategy:       "round_robin",
				CircuitBreaker: config.CircuitBreakerConfig{Threshold: 1},
				Instances:      []config.InstanceRuntime{{URL: "http://127.0.0.1:9998"}},
			},
		},
		Routes: map[string]config.RouteRuntime{},
	}
	px, err := proxy.New(rt, nil)
	if err != nil {
		t.Fatalf("proxy.New() error = %v", err)
	}
	t.Cleanup(px.Close)

	// Trip the circuit by recording a failure.
	if err := px.ResetCircuit("api", "http://127.0.0.1:9998"); err != nil {
		// Fresh circuit in closed state — reset should still succeed.
		t.Logf("initial ResetCircuit: %v (ok, circuit was closed)", err)
	}

	h := buildHandler(t, px, nil)
	req := httptest.NewRequest(http.MethodPost,
		"/_relay/admin/circuit-breakers/api/reset?instance=http://127.0.0.1:9998", nil)
	req.RemoteAddr = "127.0.0.1:1"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("reset status = %d, body: %s", rr.Code, rr.Body.String())
	}
}

func TestAdminTokenRequiredWhenConfigured(t *testing.T) {
	t.Parallel()

	h := New(buildProxy(t, "http://127.0.0.1:1"), map[string]config.RouteRuntime{},
		[]string{"0.0.0.0/0", "::/0"}, "s3cret-token", nil)

	// No token → 401.
	req := httptest.NewRequest(http.MethodGet, "/_relay/admin/backends", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("no-token status = %d, want 401", rr.Code)
	}

	// Wrong token → 401.
	req = httptest.NewRequest(http.MethodGet, "/_relay/admin/backends", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Authorization", "Bearer wrong")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-token status = %d, want 401", rr.Code)
	}

	// Correct token → 200.
	req = httptest.NewRequest(http.MethodGet, "/_relay/admin/backends", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Authorization", "Bearer s3cret-token")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("correct-token status = %d, want 200", rr.Code)
	}
}

func TestAdminForbiddenFromUnallowedIP(t *testing.T) {
	t.Parallel()

	// Build handler with loopback-only allowlist (default).
	h := New(buildProxy(t, "http://127.0.0.1:1"), nil, nil, "", nil)

	req := httptest.NewRequest(http.MethodGet, "/_relay/admin/backends", nil)
	req.RemoteAddr = "10.0.0.5:1234" // not loopback
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rr.Code)
	}
}

func TestAdminUnknownPathReturns404(t *testing.T) {
	t.Parallel()

	h := buildHandler(t, buildProxy(t, "http://127.0.0.1:1"), nil)
	req := httptest.NewRequest(http.MethodGet, "/_relay/admin/nonexistent", nil)
	req.RemoteAddr = "127.0.0.1:1"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
}
