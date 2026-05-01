package listener

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"net/http"
	"net/http/httptest"

	"algoryn.io/relay/internal/config"
	"algoryn.io/relay/internal/observability"
)

func TestServerLogsRequestToFileEndToEnd(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "access.log")

	var backendCalls atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"ok": "true"})
	}))
	t.Cleanup(backend.Close)

	cfg := &config.Config{
		Listener: config.ListenerConfig{
			HTTP: config.HTTPConfig{Port: 8080},
			Timeouts: config.TimeoutsConfig{
				Read:  30 * time.Second,
				Write: 30 * time.Second,
				Idle:  60 * time.Second,
			},
		},
		Routes: []config.RouteConfig{
			{
				Name:    "test-route",
				Backend: "test-backend",
				Match: config.MatchConfig{
					Path:    "/test",
					Methods: []string{http.MethodGet},
				},
			},
		},
		Backends: []config.BackendConfig{
			{
				Name:     "test-backend",
				Strategy: "round_robin",
				Instances: []config.InstanceConfig{
					{URL: backend.URL},
				},
			},
		},
		Middleware: []config.MiddlewareConfig{},
		Observability: config.ObservabilityConfig{
			Logs: config.LogsConfig{
				Level:     "info",
				Format:    "json",
				File:      logPath,
				MaxSizeMB: 1,
			},
			Metrics: config.MetricsConfig{
				FlushInterval: 30 * time.Second,
			},
		},
		Storage: config.StorageConfig{Path: filepath.Join(tempDir, "relay.db")},
		Reload:  config.ReloadConfig{Watch: true, Debounce: 500 * time.Millisecond},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	rt, err := config.BuildRuntime(cfg)
	if err != nil {
		t.Fatalf("BuildRuntime() error = %v", err)
	}

	logger, closer, err := observability.NewAccessLogger(cfg.Observability.Logs)
	if err != nil {
		t.Fatalf("NewAccessLogger() error = %v", err)
	}
	t.Cleanup(func() {
		if closer != nil {
			_ = closer.Close()
		}
	})

	server, err := New(cfg, rt, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if backendCalls.Load() != 1 {
		t.Fatalf("backend calls = %d, want 1", backendCalls.Load())
	}

	if err := server.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	if err := closer.Close(); err != nil {
		t.Fatalf("log closer Close() error = %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", logPath, err)
	}
	content := string(data)
	if strings.TrimSpace(content) == "" {
		t.Fatal("log file is empty")
	}
	if !strings.Contains(content, `"method":"GET"`) {
		t.Fatalf("log does not contain method GET: %q", content)
	}
	if !strings.Contains(content, `"path":"/test"`) {
		t.Fatalf("log does not contain path /test: %q", content)
	}
	if !strings.Contains(content, `"status":200`) {
		t.Fatalf("log does not contain status 200: %q", content)
	}
}
