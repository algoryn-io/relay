package listener

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"algoryn.io/relay/internal/config"
)

func TestServerWithFabricEnabledHandlesRequest(t *testing.T) {
	t.Parallel()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(backend.Close)

	rt := &config.RuntimeConfig{
		Routes: map[string]config.RouteRuntime{
			"orders-route": {
				Name:        "orders-route",
				Path:        "/api/orders",
				Methods:     []string{http.MethodGet},
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

	cfg := testServerConfig(config.ListenerConfig{
		HTTP: config.HTTPConfig{Port: 8080},
		Timeouts: config.TimeoutsConfig{
			Read:  30 * time.Second,
			Write: 30 * time.Second,
			Idle:  60 * time.Second,
		},
	})
	cfg.Storage = config.StorageConfig{Path: t.TempDir() + "/relay.db"}
	cfg.Reload = config.ReloadConfig{Debounce: time.Millisecond}
	cfg.Observability.Fabric = config.FabricConfig{
		Enabled:     true,
		ServiceName: "relay-test",
		QueueSize:   32,
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	srv, err := New(cfg, rt, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		_ = srv.Shutdown(t.Context())
	})

	req := httptest.NewRequest(http.MethodGet, "/api/orders", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}
