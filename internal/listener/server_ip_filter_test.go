package listener

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"algoryn.io/relay/internal/config"
)

func TestServerIPFilterRouteAllowedAndBlocked(t *testing.T) {
	t.Parallel()

	server, backendCalls := newIPFilterTestServer(t)

	allowedReq := httptest.NewRequest(http.MethodGet, "/admin", nil)
	allowedReq.RemoteAddr = "192.168.1.10:1234"
	allowedRec := httptest.NewRecorder()
	server.ServeHTTP(allowedRec, allowedReq)

	if allowedRec.Code != http.StatusOK {
		t.Fatalf("allowed status = %d, want %d", allowedRec.Code, http.StatusOK)
	}
	if got := backendCalls.Load(); got != 1 {
		t.Fatalf("backend calls after allowed request = %d, want 1", got)
	}

	blockedReq := httptest.NewRequest(http.MethodGet, "/admin", nil)
	blockedReq.RemoteAddr = "10.10.10.10:9999"
	blockedRec := httptest.NewRecorder()
	server.ServeHTTP(blockedRec, blockedReq)

	if blockedRec.Code != http.StatusForbidden {
		t.Fatalf("blocked status = %d, want %d", blockedRec.Code, http.StatusForbidden)
	}
	var body map[string]string
	if err := json.NewDecoder(blockedRec.Body).Decode(&body); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if body["error"] != "forbidden" {
		t.Fatalf("error = %q, want forbidden", body["error"])
	}
	if got := backendCalls.Load(); got != 1 {
		t.Fatalf("backend calls after blocked request = %d, want 1", got)
	}
}

func newIPFilterTestServer(t *testing.T) (*Server, *atomic.Int64) {
	t.Helper()

	var backendCalls atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"service": "admin-backend",
			"path":    r.URL.Path,
		})
	}))
	t.Cleanup(backend.Close)

	rt := &config.RuntimeConfig{
		Routes: map[string]config.RouteRuntime{
			"admin-route": {
				Name:           "admin-route",
				Path:           "/admin",
				Methods:        []string{http.MethodGet},
				BackendName:    "admin-backend",
				MiddlewareRefs: []string{"admin-ip-filter"},
			},
		},
		Backends: map[string]config.BackendRuntime{
			"admin-backend": {
				Name:     "admin-backend",
				Strategy: "round_robin",
				Instances: []config.InstanceRuntime{
					{URL: backend.URL},
				},
			},
		},
		Middleware: map[string]config.MiddlewareRuntime{
			"admin-ip-filter": {
				Name: "admin-ip-filter",
				Type: "ip_filter",
				Config: config.MiddlewareSettingsConfig{
					Allow: []string{"192.168.1.0/24"},
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
	return server, &backendCalls
}
