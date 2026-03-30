package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"algoryn.io/relay/internal/config"
)

func TestProxySuccessfulRequest(t *testing.T) {
	t.Parallel()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"service": "orders",
			"path":    r.URL.Path,
			"method":  r.Method,
		})
	}))
	defer backend.Close()

	p := newTestProxy(t, map[string]config.BackendRuntime{
		"orders-backend": {
			Name: "orders-backend",
			Instances: []config.InstanceRuntime{
				{URL: backend.URL},
			},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/orders", nil)
	req.RemoteAddr = "203.0.113.10:1234"
	rec := httptest.NewRecorder()

	p.ServeHTTP(rec, req, &config.RouteRuntime{BackendName: "orders-backend"})

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if body["service"] != "orders" {
		t.Fatalf("service = %q, want orders", body["service"])
	}
	if body["path"] != "/api/orders" {
		t.Fatalf("path = %q, want /api/orders", body["path"])
	}
	if body["method"] != http.MethodGet {
		t.Fatalf("method = %q, want %s", body["method"], http.MethodGet)
	}
}

func TestProxySetsForwardedHeaders(t *testing.T) {
	t.Parallel()

	received := make(chan http.Header, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	p := newTestProxy(t, map[string]config.BackendRuntime{
		"orders-backend": {
			Name: "orders-backend",
			Instances: []config.InstanceRuntime{
				{URL: backend.URL},
			},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/orders", nil)
	req.Host = "relay.local"
	req.RemoteAddr = "203.0.113.10:4321"
	rec := httptest.NewRecorder()

	p.ServeHTTP(rec, req, &config.RouteRuntime{BackendName: "orders-backend"})

	headers := <-received
	if got := headers.Get("X-Forwarded-Host"); got != "relay.local" {
		t.Fatalf("X-Forwarded-Host = %q, want relay.local", got)
	}
	if got := headers.Get("X-Forwarded-Proto"); got != "http" {
		t.Fatalf("X-Forwarded-Proto = %q, want http", got)
	}
	if got := headers.Get("X-Forwarded-For"); got != "203.0.113.10" {
		t.Fatalf("X-Forwarded-For = %q, want 203.0.113.10", got)
	}
}

func TestProxyBackendDownReturns502(t *testing.T) {
	t.Parallel()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	backendURL := backend.URL
	backend.Close()

	p := newTestProxy(t, map[string]config.BackendRuntime{
		"orders-backend": {
			Name: "orders-backend",
			Instances: []config.InstanceRuntime{
				{URL: backendURL},
			},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/orders", nil)
	rec := httptest.NewRecorder()

	p.ServeHTTP(rec, req, &config.RouteRuntime{BackendName: "orders-backend"})

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadGateway)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if body["error"] != "bad_gateway" {
		t.Fatalf("error = %q, want bad_gateway", body["error"])
	}
	if body["status"] != "error" {
		t.Fatalf("status = %q, want error", body["status"])
	}
}

func TestProxyNoInstancesReturns502(t *testing.T) {
	t.Parallel()

	p := newTestProxy(t, map[string]config.BackendRuntime{
		"orders-backend": {
			Name: "orders-backend",
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/orders", nil)
	rec := httptest.NewRecorder()

	p.ServeHTTP(rec, req, &config.RouteRuntime{BackendName: "orders-backend"})

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadGateway)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if body["error"] != "bad_gateway" {
		t.Fatalf("error = %q, want bad_gateway", body["error"])
	}
	if body["status"] != "error" {
		t.Fatalf("status = %q, want error", body["status"])
	}
}

func newTestProxy(t *testing.T, backends map[string]config.BackendRuntime) *Proxy {
	t.Helper()

	p, err := New(&config.RuntimeConfig{Backends: backends})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	return p
}
