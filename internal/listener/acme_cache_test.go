package listener

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"algoryn.io/relay/internal/config"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/acme/autocert"
)

func TestRedisACMECacheImplementsAutocertCache(t *testing.T) {
	var _ autocert.Cache = (*redisACMECache)(nil)
}

func TestRedisACMECacheCoordinatesConcurrentMiss(t *testing.T) {
	mr := miniredis.RunT(t)
	client1 := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	client2 := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() {
		_ = client1.Close()
		_ = client2.Close()
	})
	cfg := testRedisACMEConfig()
	cache1 := mustRedisACMECache(t, client1, cfg)
	cache2 := mustRedisACMECache(t, client2, cfg)
	t.Cleanup(func() {
		_ = cache1.Close()
		_ = cache2.Close()
	})

	if _, err := cache1.Get(context.Background(), "example.com"); !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("first Get() error = %v, want autocert.ErrCacheMiss", err)
	}

	type result struct {
		data []byte
		err  error
	}
	resultCh := make(chan result, 1)
	go func() {
		data, err := cache2.Get(context.Background(), "example.com")
		resultCh <- result{data: data, err: err}
	}()

	select {
	case got := <-resultCh:
		t.Fatalf("second replica returned before issuance completed: %+v", got)
	case <-time.After(30 * time.Millisecond):
	}
	if err := cache1.Put(context.Background(), "example.com", []byte("certificate")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	select {
	case got := <-resultCh:
		if got.err != nil || string(got.data) != "certificate" {
			t.Fatalf("coordinated Get() = %q, %v", got.data, got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("second replica did not observe published certificate")
	}
}

func TestRedisACMECacheFailsClosedWhenRedisUnavailable(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	cache := mustRedisACMECache(t, client, testRedisACMEConfig())
	mr.Close()
	t.Cleanup(func() {
		_ = cache.Close()
		_ = client.Close()
	})

	_, err := cache.Get(context.Background(), "example.com")
	if err == nil || errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("Get() error = %v, want fail-closed Redis error", err)
	}
}

func TestRedisACMECacheRejectsStaleOwnerWrite(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	cache := mustRedisACMECache(t, client, testRedisACMEConfig())
	t.Cleanup(func() {
		_ = cache.Close()
		_ = client.Close()
	})

	const key = "example.com"
	if _, err := cache.Get(context.Background(), key); !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("Get() error = %v, want autocert.ErrCacheMiss", err)
	}
	dataKey, lockKey := cache.keys(key)
	mr.Set(lockKey, "replacement-owner")
	if err := cache.Put(context.Background(), key, []byte("stale-certificate")); err == nil {
		t.Fatal("Put() succeeded after lease owner changed")
	}
	if mr.Exists(dataKey) {
		t.Fatal("stale owner wrote ACME cache data")
	}
	if got, _ := mr.Get(lockKey); got != "replacement-owner" {
		t.Fatalf("stale owner released replacement lease: %q", got)
	}
}

func TestRedisACMECacheRenewsOwnedLease(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	cfg := testRedisACMEConfig()
	cfg.ACMECache.LockTTL = 100 * time.Millisecond
	cfg.ACMECache.LockRenewInterval = 20 * time.Millisecond
	cache := mustRedisACMECache(t, client, cfg)
	t.Cleanup(func() {
		_ = cache.Close()
		_ = client.Close()
	})

	const key = "example.com"
	if _, err := cache.Get(context.Background(), key); !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("Get() error = %v, want autocert.ErrCacheMiss", err)
	}
	_, lockKey := cache.keys(key)
	mr.FastForward(80 * time.Millisecond)
	time.Sleep(60 * time.Millisecond)
	mr.FastForward(50 * time.Millisecond)
	if !mr.Exists(lockKey) {
		t.Fatal("owned issuance lease expired instead of being renewed")
	}
}

func TestRedisACMECacheStopsRenewingAbandonedLease(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	cfg := testRedisACMEConfig()
	cfg.ACMECache.LockWaitTimeout = 40 * time.Millisecond
	cfg.ACMECache.LockTTL = 100 * time.Millisecond
	cfg.ACMECache.LockRenewInterval = 10 * time.Millisecond
	cache := mustRedisACMECache(t, client, cfg)
	t.Cleanup(func() {
		_ = cache.Close()
		_ = client.Close()
	})

	const key = "example.com"
	if _, err := cache.Get(context.Background(), key); !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("Get() error = %v, want autocert.ErrCacheMiss", err)
	}
	time.Sleep(80 * time.Millisecond)
	if lease := cache.currentLease(key); lease != nil {
		t.Fatal("abandoned local issuance lease remained registered")
	}
	_, lockKey := cache.keys(key)
	mr.FastForward(101 * time.Millisecond)
	if mr.Exists(lockKey) {
		t.Fatal("abandoned Redis issuance lease remained renewed")
	}
}

func TestACMERedisNamespaceSeparatesDomainsAndAccounts(t *testing.T) {
	a := acmeRedisNamespace("production", "ops@example.com", []string{"b.example.com", "A.example.com"})
	b := acmeRedisNamespace("production", "ops@example.com", []string{"a.example.com", "b.example.com"})
	if a != b {
		t.Fatalf("domain ordering changed namespace: %q != %q", a, b)
	}
	if a == acmeRedisNamespace("production", "other@example.com", []string{"a.example.com", "b.example.com"}) {
		t.Fatal("different ACME accounts shared namespace")
	}
	if a == acmeRedisNamespace("production", "ops@example.com", []string{"other.example.com"}) {
		t.Fatal("different domain sets shared namespace")
	}
	if !strings.HasPrefix(a, "relay:acme:production:") {
		t.Fatalf("namespace = %q", a)
	}
}

func TestRedisACMECacheLifecycleAcrossReloadAndShutdown(t *testing.T) {
	mr := miniredis.RunT(t)
	cfg := &config.Config{Listener: config.ListenerConfig{
		HTTPS: config.HTTPSConfig{
			Port: 8443,
			TLS:  testRedisACMEConfig(),
		},
	}}
	cfg.Listener.HTTPS.TLS.Mode = "auto"
	cfg.Listener.HTTPS.TLS.ACMECache.RedisURL = "redis://" + mr.Addr()
	runtime := &config.RuntimeConfig{
		Routes:     map[string]config.RouteRuntime{},
		Backends:   map[string]config.BackendRuntime{},
		Middleware: map[string]config.MiddlewareRuntime{},
	}
	server, err := New(cfg, runtime, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	server.drainTimeout = 10 * time.Millisecond
	oldCache, ok := server.tlsResource.(*redisACMECache)
	if !ok {
		t.Fatalf("TLS resource type = %T", server.tlsResource)
	}
	if err := server.Reload(cfg, runtime); err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	deadline := time.Now().Add(time.Second)
	for !oldCache.isClosed() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !oldCache.isClosed() {
		t.Fatal("old ACME Redis cache remained open after reload drain")
	}
	currentCache, ok := server.tlsResource.(*redisACMECache)
	if !ok {
		t.Fatalf("reloaded TLS resource type = %T", server.tlsResource)
	}
	if err := server.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	if !currentCache.isClosed() {
		t.Fatal("current ACME Redis cache remained open after shutdown")
	}
}

func mustRedisACMECache(t *testing.T, client redis.Cmdable, cfg config.TLSConfig) *redisACMECache {
	t.Helper()
	cache, err := newRedisACMECacheFromClient(client, nil, cfg)
	if err != nil {
		t.Fatalf("newRedisACMECacheFromClient() error = %v", err)
	}
	return cache
}

func testRedisACMEConfig() config.TLSConfig {
	return config.TLSConfig{
		Domains:     []string{"example.com"},
		ACMEEmail:   "ops@example.com",
		Distributed: true,
		Replicas:    2,
		ACMECache: config.ACMECacheConfig{
			Backend:           "redis",
			Namespace:         "test",
			OperationTimeout:  100 * time.Millisecond,
			LockWaitTimeout:   time.Second,
			LockTTL:           time.Second,
			LockRenewInterval: 200 * time.Millisecond,
		},
	}
}
