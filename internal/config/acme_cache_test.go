package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidateACMECacheReplicaSafety(t *testing.T) {
	cfg := validConfig()
	cfg.Listener.HTTP.CanonicalHost = "api.example.com"
	cfg.Listener.HTTPS = HTTPSConfig{
		Port: 443,
		TLS: TLSConfig{
			Mode:     "auto",
			Domains:  []string{"api.example.com"},
			Replicas: 2,
			ACMECache: ACMECacheConfig{
				Backend:   "filesystem",
				Directory: t.TempDir(),
			},
		},
	}
	assertValidationErrorContains(t, cfg.Validate(), "multiple replicas require distributed: true")

	cfg.Listener.HTTPS.TLS.ACMECache = ACMECacheConfig{
		Backend:  "redis",
		RedisURL: "redis://localhost:6379/0",
	}
	assertValidationErrorContains(t, cfg.Validate(), "distributed: must be true")

	cfg.Listener.HTTPS.TLS.Distributed = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() distributed ACME config error = %v", err)
	}
}

func TestLoadACMECacheDurationsAndResolveSecretSources(t *testing.T) {
	dir := t.TempDir()
	redisSecret := filepath.Join(dir, "redis-url")
	if err := os.WriteFile(redisSecret, []byte("redis://file.example:6379/0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "relay.yaml")
	yaml := `
listener:
  https:
    port: 443
    tls:
      mode: auto
      domains: [api.example.com]
      replicas: 2
      distributed: true
      acme_cache:
        backend: redis
        redis_url_env: ACME_REDIS_URL
        redis_url_file: ` + redisSecret + `
        operation_timeout: 250ms
        lock_wait_timeout: 4m
        lock_ttl: 90s
        lock_renew_interval: 20s
routes: []
backends: []
middleware: []
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.ResolveEnv(func(name string) string {
		if name == "ACME_REDIS_URL" {
			return "redis://env.example:6379/0"
		}
		return ""
	}); err != nil {
		t.Fatal(err)
	}
	if err := cfg.ResolveSecretFiles(nil); err != nil {
		t.Fatal(err)
	}
	cache := cfg.Listener.HTTPS.TLS.ACMECache
	if cache.RedisURL != "redis://env.example:6379/0" {
		t.Fatalf("RedisURL = %q, env source did not win", cache.RedisURL)
	}
	if cache.OperationTimeout != 250*time.Millisecond || cache.LockWaitTimeout != 4*time.Minute ||
		cache.LockTTL != 90*time.Second || cache.LockRenewInterval != 20*time.Second {
		t.Fatalf("unexpected parsed ACME cache durations: %+v", cache)
	}
}

func TestValidateACMECacheRejectsUnsafeLeaseDurations(t *testing.T) {
	cfg := validConfig()
	cfg.Listener.HTTP.CanonicalHost = "api.example.com"
	cfg.Listener.HTTPS = HTTPSConfig{
		Port: 443,
		TLS: TLSConfig{
			Mode:        "auto",
			Domains:     []string{"api.example.com"},
			Distributed: true,
			ACMECache: ACMECacheConfig{
				Backend:           "redis",
				RedisURL:          "redis://localhost:6379",
				LockTTL:           10 * time.Second,
				LockRenewInterval: 10 * time.Second,
			},
		},
	}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "must be less than lock_ttl") {
		t.Fatalf("Validate() error = %v", err)
	}
}
