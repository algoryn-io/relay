package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
    canonical_host: api.example.com
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
  logs:
    level: info
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
	if got := cfg.Observability.Logs.Level; got != "info" {
		t.Fatalf("log level = %q, want info", got)
	}
}

func TestLoadTracingSampleRateDistinguishesZeroFromDefault(t *testing.T) {
	t.Parallel()
	explicitPath := writeTempConfig(t, `
observability:
  tracing:
    enabled: true
    exporter: stdout
    sample_rate: 0
`)
	explicit, err := Load(explicitPath)
	if err != nil {
		t.Fatal(err)
	}
	if explicit.Observability.Tracing.SampleRate != 0 || !explicit.Observability.Tracing.SampleRateSet {
		t.Fatalf("explicit zero sample rate was not preserved: %+v", explicit.Observability.Tracing)
	}

	defaultPath := writeTempConfig(t, `
observability:
  tracing:
    enabled: true
    exporter: stdout
`)
	defaulted, err := Load(defaultPath)
	if err != nil {
		t.Fatal(err)
	}
	if defaulted.Observability.Tracing.SampleRate != 1 || defaulted.Observability.Tracing.SampleRateSet {
		t.Fatalf("default sample rate was not applied: %+v", defaulted.Observability.Tracing)
	}
}

func TestLoadDangerousOptionAcknowledgements(t *testing.T) {
	t.Parallel()

	path := writeTempConfig(t, `
middleware:
  - name: query-key
    type: api_key
    config:
      key_query: api_key
      acknowledge_api_key_in_query: true
  - name: external-authz
    type: ext_authz
    config:
      fail_open: true
      acknowledge_ext_authz_fail_open: true
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.Middleware[0].Config.AcknowledgeAPIKeyInQuery {
		t.Fatal("acknowledge_api_key_in_query was not decoded")
	}
	if !cfg.Middleware[1].Config.AcknowledgeExtAuthzFailOpen {
		t.Fatal("acknowledge_ext_authz_fail_open was not decoded")
	}
}

func TestLoadJWKSStaleGrace(t *testing.T) {
	t.Parallel()

	path := writeTempConfig(t, `
middleware:
  - name: jwt-remote
    type: jwt
    config:
      algorithm: rs256
      jwks_url: https://issuer.example.com/jwks
      jwks_cache_ttl: 5m
      jwks_stale_grace: 10m
      issuer: https://issuer.example.com
      audience: relay-api
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got := cfg.Middleware[0].Config.JWKSStaleGrace; got != 10*time.Minute {
		t.Fatalf("JWKSStaleGrace = %s, want 10m", got)
	}
}

func TestLoadSecurityHeadersAndRedirectHosts(t *testing.T) {
	t.Parallel()

	path := writeTempConfig(t, `
listener:
  http:
    port: 80
    redirect_allowed_hosts: [api.example.com, "2001:db8::1"]
middleware:
  - name: browser-security
    type: security_headers
    config:
      preset: secure
      x_frame_options: off
      content_security_policy: "default-src 'self'; frame-ancestors 'self'"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got := cfg.Listener.HTTP.RedirectAllowedHosts; len(got) != 2 {
		t.Fatalf("RedirectAllowedHosts = %#v", got)
	}
	if got := cfg.Middleware[0].Config.SecurityHeadersPreset; got != "secure" {
		t.Fatalf("SecurityHeadersPreset = %q, want secure", got)
	}
}

func TestLoadRejectsRemovedLegacyFields(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		contents string
		field    string
	}{
		"dashboard": {contents: `
observability:
  dashboard:
    enabled: true
`, field: "dashboard"},
		"storage": {contents: `
storage:
  path: ./data
`, field: "storage"},
		"metrics.flush_interval": {contents: `
observability:
  metrics:
    flush_interval: 30s
`, field: "metrics"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := Load(writeTempConfig(t, tc.contents))
			if err == nil {
				t.Fatal("Load() error = nil, want unknown-field error")
			}
			want := "field " + tc.field + " not found"
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("Load() error = %q, want substring %q", err, want)
			}
		})
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
