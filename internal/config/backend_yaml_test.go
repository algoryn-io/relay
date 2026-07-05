package config

import "testing"

// TestLoadBackendRetryTLSBulkheadFromYAML is a regression test for a bug where
// BackendConfig.UnmarshalYAML dropped the retry, tls and bulkhead blocks: they
// were absent from the internal rawBackend struct, so these features silently
// did nothing when configured via YAML (the only way users configure them).
func TestLoadBackendRetryTLSBulkheadFromYAML(t *testing.T) {
	t.Parallel()

	path := writeTempConfig(t, `
listener:
  http:
    port: 8080
routes:
  - name: r
    match:
      path: /x
      methods: [GET]
    backend: b
backends:
  - name: b
    strategy: round_robin
    retry:
      attempts: 3
      backoff_init: 100ms
      backoff_max: 1s
      on: [5xx, network_error]
      allow_unsafe: true
    bulkhead:
      max_concurrent: 7
    tls:
      ca_file: /etc/relay/ca.pem
      cert_file: /etc/relay/client.pem
      key_file: /etc/relay/client-key.pem
    instances:
      - url: https://localhost:9001
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	b := cfg.Backends[0]

	if b.Retry.Attempts != 3 {
		t.Errorf("retry.attempts = %d, want 3", b.Retry.Attempts)
	}
	if b.Retry.BackoffInit.String() != "100ms" {
		t.Errorf("retry.backoff_init = %s, want 100ms", b.Retry.BackoffInit)
	}
	if len(b.Retry.On) != 2 || b.Retry.On[0] != "5xx" || b.Retry.On[1] != "network_error" {
		t.Errorf("retry.on = %v, want [5xx network_error]", b.Retry.On)
	}
	if !b.Retry.AllowUnsafe {
		t.Error("retry.allow_unsafe = false, want true")
	}
	if b.Bulkhead.MaxConcurrent != 7 {
		t.Errorf("bulkhead.max_concurrent = %d, want 7", b.Bulkhead.MaxConcurrent)
	}
	if b.TLS.CAFile != "/etc/relay/ca.pem" {
		t.Errorf("tls.ca_file = %q, want /etc/relay/ca.pem", b.TLS.CAFile)
	}
	if b.TLS.CertFile != "/etc/relay/client.pem" {
		t.Errorf("tls.cert_file = %q, want /etc/relay/client.pem", b.TLS.CertFile)
	}
	if b.TLS.KeyFile != "/etc/relay/client-key.pem" {
		t.Errorf("tls.key_file = %q, want /etc/relay/client-key.pem", b.TLS.KeyFile)
	}
}
