package listener

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"algoryn.io/relay/internal/config"
)

func TestServerMatchedRouteReturns200(t *testing.T) {
	t.Parallel()

	server := newTestServer(t)
	resp := performRequest(t, server, http.MethodGet, "/api/orders")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var body map[string]string
	decodeJSON(t, resp.Body, &body)
	if body["service"] != "orders" {
		t.Fatalf("service = %q, want orders", body["service"])
	}
	if body["path"] != "/api/orders" {
		t.Fatalf("path = %q, want /api/orders", body["path"])
	}
}

func TestServerUnknownRouteReturns404(t *testing.T) {
	t.Parallel()

	server := newTestServer(t)
	resp := performRequest(t, server, http.MethodGet, "/unknown")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}

	var body map[string]string
	decodeJSON(t, resp.Body, &body)
	if body["error"] != "not_found" {
		t.Fatalf("error = %q, want not_found", body["error"])
	}
	if body["status"] != "error" {
		t.Fatalf("status = %q, want error", body["status"])
	}
}

func TestServerWrongMethodReturns405(t *testing.T) {
	t.Parallel()

	server := newTestServer(t)
	resp := performRequest(t, server, http.MethodDelete, "/api/orders")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}

	var body map[string]string
	decodeJSON(t, resp.Body, &body)
	if body["error"] != "method_not_allowed" {
		t.Fatalf("error = %q, want method_not_allowed", body["error"])
	}
	if body["status"] != "error" {
		t.Fatalf("status = %q, want error", body["status"])
	}
}

func TestServerMetricsAllowsLocalhost(t *testing.T) {
	t.Parallel()

	server := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/_relay/metrics", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()

	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestServerMetricsRejectsNonLocalhost(t *testing.T) {
	t.Parallel()

	server := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/_relay/metrics", nil)
	req.RemoteAddr = "203.0.113.10:1234"
	rec := httptest.NewRecorder()

	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	var body map[string]string
	decodeJSON(t, rec.Body, &body)
	if body["error"] != "forbidden" {
		t.Fatalf("error = %q, want forbidden", body["error"])
	}
}

func TestServerShutdown(t *testing.T) {
	t.Parallel()

	server := newTestServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
}

func newTestServer(t *testing.T) *Server {
	t.Helper()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"service": "orders",
			"path":    r.URL.Path,
		})
	}))
	t.Cleanup(backend.Close)

	rt := &config.RuntimeConfig{
		Routes: map[string]config.RouteRuntime{
			"orders-route": {
				Name:        "orders-route",
				Path:        "/api/orders",
				Methods:     []string{http.MethodGet, http.MethodPost},
				BackendName: "orders-backend",
			},
		},
		Backends: map[string]config.BackendRuntime{
			"orders-backend": {
				Name: "orders-backend",
				Instances: []config.InstanceRuntime{
					{URL: backend.URL},
				},
			},
		},
	}

	server, err := New(testServerConfig(config.ListenerConfig{
		HTTP: config.HTTPConfig{Port: 8080},
		Timeouts: config.TimeoutsConfig{
			Read:  30 * time.Second,
			Write: 30 * time.Second,
			Idle:  60 * time.Second,
		},
	}), rt, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	return server
}

func performRequest(t *testing.T, server *Server, method, path string) *http.Response {
	t.Helper()

	req := httptest.NewRequest(method, path, nil)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	return rec.Result()
}

func decodeJSON(t *testing.T, body io.Reader, dst any) {
	t.Helper()
	if err := json.NewDecoder(body).Decode(dst); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
}
