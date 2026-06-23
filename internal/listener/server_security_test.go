package listener

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"algoryn.io/relay/internal/config"
)

// A spoofed X-Forwarded-For must not grant access to the loopback-gated metrics
// endpoint: the gate uses the real TCP peer, not the forwarded client IP.
func TestServerMetricsRejectsSpoofedXFF(t *testing.T) {
	t.Parallel()

	server := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/_relay/metrics", nil)
	req.RemoteAddr = "203.0.113.10:1234"
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	rec := httptest.NewRecorder()

	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (spoofed XFF must not bypass gate)", rec.Code)
	}
}

// The Prometheus endpoint must be gated to the local peer, like the JSON metrics
// endpoint.
func TestServerPrometheusRequiresLoopback(t *testing.T) {
	t.Parallel()

	server := newTestServer(t)

	remote := httptest.NewRequest(http.MethodGet, "/_relay/metrics/prometheus", nil)
	remote.RemoteAddr = "203.0.113.10:1234"
	recRemote := httptest.NewRecorder()
	server.ServeHTTP(recRemote, remote)
	if recRemote.Code != http.StatusForbidden {
		t.Fatalf("remote prometheus status = %d, want 403", recRemote.Code)
	}

	local := httptest.NewRequest(http.MethodGet, "/_relay/metrics/prometheus", nil)
	local.RemoteAddr = "127.0.0.1:5555"
	recLocal := httptest.NewRecorder()
	server.ServeHTTP(recLocal, local)
	if recLocal.Code != http.StatusOK {
		t.Fatalf("local prometheus status = %d, want 200", recLocal.Code)
	}
}

// Spoofed identity headers must be stripped at the edge before reaching the
// backend, so a client cannot forge an authenticated identity.
func TestServerStripsSpoofedIdentityHeaders(t *testing.T) {
	t.Parallel()

	var gotSub, gotXFF string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSub = r.Header.Get("X-Authenticated-Sub")
		gotXFF = r.Header.Get("X-Forwarded-For")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(backend.Close)

	rt := &config.RuntimeConfig{
		Routes: map[string]config.RouteRuntime{
			"pub": {Name: "pub", Path: "/pub", Methods: []string{http.MethodGet}, BackendName: "b"},
		},
		Backends: map[string]config.BackendRuntime{
			"b": {Name: "b", Instances: []config.InstanceRuntime{{URL: backend.URL}}},
		},
	}
	server, err := New(testServerConfig(config.ListenerConfig{
		HTTP:     config.HTTPConfig{Port: 8080},
		Timeouts: config.TimeoutsConfig{Read: 5 * time.Second, Write: 5 * time.Second, Idle: 5 * time.Second},
	}), rt, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/pub", nil)
	req.RemoteAddr = "203.0.113.7:9999" // untrusted peer
	req.Header.Set("X-Authenticated-Sub", "admin")
	req.Header.Set("X-Forwarded-For", "10.9.9.9")
	server.ServeHTTP(httptest.NewRecorder(), req)

	if gotSub != "" {
		t.Errorf("backend received spoofed X-Authenticated-Sub = %q, want empty", gotSub)
	}
	// The proxy sets its own X-Forwarded-For (the real peer), never the spoofed one.
	if gotXFF == "10.9.9.9" {
		t.Errorf("backend received spoofed X-Forwarded-For = %q", gotXFF)
	}
}

// With a global cap of 1 and a slow backend, a second concurrent request must be
// shed with 503 while the first is still in flight; internal endpoints stay up.
func TestServerGlobalBackpressureShedsExcess(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release // hold the request open
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(backend.Close)

	rt := &config.RuntimeConfig{
		Routes: map[string]config.RouteRuntime{
			"r": {Name: "r", Path: "/x", Methods: []string{http.MethodGet}, BackendName: "b"},
		},
		Backends: map[string]config.BackendRuntime{
			"b": {Name: "b", Instances: []config.InstanceRuntime{{URL: backend.URL}}},
		},
	}
	server, err := New(testServerConfig(config.ListenerConfig{
		HTTP:                  config.HTTPConfig{Port: 8080},
		MaxConcurrentRequests: 1,
		Timeouts:              config.TimeoutsConfig{Read: 5 * time.Second, Write: 5 * time.Second, Idle: 5 * time.Second},
	}), rt, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// First request occupies the only slot.
	firstDone := make(chan int, 1)
	go func() {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		server.ServeHTTP(rec, req)
		firstDone <- rec.Code
	}()

	// Wait until the backend is actually handling the first request.
	waitUntil(t, func() bool { return server.inFlight.Load() == 1 })

	// Second request must be shed immediately.
	rec2 := httptest.NewRecorder()
	server.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec2.Code != http.StatusServiceUnavailable {
		t.Fatalf("second request status = %d, want 503", rec2.Code)
	}

	// Internal endpoints stay reachable under overload.
	recHealth := httptest.NewRecorder()
	server.ServeHTTP(recHealth, httptest.NewRequest(http.MethodGet, "/_relay/health", nil))
	if recHealth.Code != http.StatusOK {
		t.Fatalf("health status under load = %d, want 200", recHealth.Code)
	}

	close(release)
	if code := <-firstDone; code != http.StatusOK {
		t.Fatalf("first request status = %d, want 200", code)
	}
}

func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("condition not met within deadline")
}

func TestServerReadinessReady(t *testing.T) {
	t.Parallel()

	server := newTestServer(t) // backend has no health check → instance healthy
	req := httptest.NewRequest(http.MethodGet, "/_relay/ready", nil)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body map[string]string
	decodeJSON(t, rec.Body, &body)
	if body["status"] != "ready" {
		t.Fatalf("status = %q, want ready", body["status"])
	}
}

func TestServerReadinessUnavailableWhenAllUnhealthy(t *testing.T) {
	t.Parallel()

	// A backend with a health check starts unhealthy until the first probe
	// succeeds. Pointing it at an unreachable address keeps it unhealthy.
	rt := &config.RuntimeConfig{
		Routes: map[string]config.RouteRuntime{
			"r": {Name: "r", Path: "/x", Methods: []string{http.MethodGet}, BackendName: "down"},
		},
		Backends: map[string]config.BackendRuntime{
			"down": {
				Name:        "down",
				HealthCheck: config.HealthCheckConfig{Path: "/health", Interval: time.Hour, Timeout: time.Second},
				Instances:   []config.InstanceRuntime{{URL: "http://127.0.0.1:1"}},
			},
		},
	}
	server, err := New(testServerConfig(config.ListenerConfig{
		HTTP:     config.HTTPConfig{Port: 8080},
		Timeouts: config.TimeoutsConfig{Read: 5 * time.Second, Write: 5 * time.Second, Idle: 5 * time.Second},
	}), rt, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = server.Shutdown(context.Background()) })

	req := httptest.NewRequest(http.MethodGet, "/_relay/ready", nil)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	var body map[string]string
	decodeJSON(t, rec.Body, &body)
	if body["status"] != "unavailable" {
		t.Fatalf("status = %q, want unavailable", body["status"])
	}
}
