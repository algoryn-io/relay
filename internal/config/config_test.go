package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadMinimalValidConfig(t *testing.T) {
	t.Parallel()

	path := writeTempConfig(t, `
listener:
  http:
    port: 8080
  timeouts:
    read: 30s
    write: 30s
    idle: 60s
routes:
  - name: orders
    match:
      path: /orders
      methods: [get]
    backend: orders-backend
backends:
  - name: orders-backend
    strategy: round_robin
    instances:
      - url: http://localhost:8080
middleware: []
observability:
  metrics:
    flush_interval: 30s
storage:
  path: ./data
reload:
  watch: true
  debounce: 500ms
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Listener.HTTP.Port != 8080 {
		t.Fatalf("HTTP port = %d, want 8080", cfg.Listener.HTTP.Port)
	}
	if cfg.Routes[0].Name != "orders" {
		t.Fatalf("route name = %q, want orders", cfg.Routes[0].Name)
	}
}

func TestLoadFullValidConfig(t *testing.T) {
	t.Parallel()

	path := writeTempConfig(t, `
listener:
  http:
    port: 80
  https:
    port: 443
    tls:
      mode: auto
      domains:
        - api.example.com
  timeouts:
    read: 30s
    write: 30s
    idle: 60s
routes:
  - name: orders-route
    match:
      path: /api/orders
      methods: [GET, POST]
    middleware: [jwt-auth]
    backend: orders-backend
backends:
  - name: orders-backend
    strategy: round_robin
    health_check:
      interval: 10s
      timeout: 2s
      path: /health
    instances:
      - url: http://localhost:8080
middleware:
  - name: jwt-auth
    type: jwt
    config:
      secret_env: JWT_SECRET
      header: Authorization
observability:
  dashboard:
    enabled: true
    port: 9090
  logs:
    level: info
  metrics:
    flush_interval: 30s
storage:
  path: ./data
  retention:
    metrics_days: 90
    logs_days: 30
reload:
  watch: true
  debounce: 500ms
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if got := cfg.Listener.HTTPS.TLS.Mode; got != "auto" {
		t.Fatalf("HTTPS TLS mode = %q, want auto", got)
	}
	if got := cfg.Observability.Dashboard.Port; got != 9090 {
		t.Fatalf("dashboard port = %d, want 9090", got)
	}
	if got := cfg.Observability.Logs.Level; got != "info" {
		t.Fatalf("log level = %q, want info", got)
	}
}

func writeTempConfig(t *testing.T, contents string) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "relay.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}
