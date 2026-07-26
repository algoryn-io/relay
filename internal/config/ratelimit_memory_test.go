package config

import (
	"testing"
	"time"
)

func TestLoadRateLimitMemoryDefaults(t *testing.T) {
	t.Parallel()
	path := writeTempConfig(t, `
listener:
  http: {port: 8080}
  timeouts: {read: 1s, write: 1s, idle: 1s}
routes: []
backends: []
middleware:
  - name: limited
    type: rate_limit
    config:
      strategy: sliding_window
      limit: 10
      window: 30s
      by: ip
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	got := cfg.Middleware[0].Config
	if got.MemoryMaxBuckets != 100_000 {
		t.Fatalf("memory_max_buckets = %d, want 100000", got.MemoryMaxBuckets)
	}
	if got.MemoryBucketTTL != 30*time.Second {
		t.Fatalf("memory_bucket_ttl = %v, want 30s", got.MemoryBucketTTL)
	}
	if got.MemoryCleanupInterval != time.Minute {
		t.Fatalf("memory_cleanup_interval = %v, want 1m", got.MemoryCleanupInterval)
	}
}

func TestValidateRateLimitMemoryBounds(t *testing.T) {
	t.Parallel()
	cfg := validConfig()
	cfg.Middleware = append(cfg.Middleware, MiddlewareConfig{
		Name: "limited",
		Type: "rate_limit",
		Config: MiddlewareSettingsConfig{
			Strategy:              "sliding_window",
			Limit:                 10,
			Window:                time.Minute,
			By:                    "ip",
			RateLimitStore:        "memory",
			MemoryMaxBuckets:      -1,
			MemoryBucketTTL:       30 * time.Second,
			MemoryCleanupInterval: -time.Second,
		},
	})
	err := cfg.Validate()
	assertValidationErrorContains(t, err, "memory_max_buckets")
	assertValidationErrorContains(t, err, "memory_bucket_ttl: must be at least")
	assertValidationErrorContains(t, err, "memory_cleanup_interval")
}

func TestLoadRateLimitCompositeKey(t *testing.T) {
	t.Parallel()
	path := writeTempConfig(t, `
listener:
  http: {port: 8080}
  timeouts: {read: 1s, write: 1s, idle: 1s}
routes: []
backends: []
middleware:
  - name: limited
    type: rate_limit
    config:
      strategy: sliding_window
      limit: 10
      window: 30s
      key:
        namespace: orders:v1
        selectors:
          - route
          - {type: header, name: X-Plan}
        fallback: ip
        reject_missing: true
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	key := cfg.Middleware[0].Config.RateLimitKey
	if len(key.Selectors) != 2 || key.Selectors[1].Name != "X-Plan" {
		t.Fatalf("selectors = %+v", key.Selectors)
	}
	if key.Fallback == nil || key.Fallback.Type != "ip" || !key.RejectMissing {
		t.Fatalf("key config = %+v", key)
	}
}
