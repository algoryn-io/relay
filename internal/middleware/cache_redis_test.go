package middleware

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newTestCacheRedis(t *testing.T, cfg CacheConfig, mr *miniredis.Miniredis) (Middleware, *cacheMiddleware) {
	t.Helper()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	cfg.StoreBackend = newCacheRedisStoreFromClient(client, nil, cfg.Namespace, cfg.OperationTimeout, cfg.MaxObjectBytes, cfg.Now)
	cfg.Store = "redis"
	mw, closer, err := NewCache(cfg)
	if err != nil {
		t.Fatalf("NewCache() error = %v", err)
	}
	t.Cleanup(func() { _ = closer.Close() })
	return mw, closer
}

func TestRedisCacheHitAcrossLookup(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)
	var calls atomic.Int64
	backend := countingBackend(&calls, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("shared"))
	})

	mw, _ := newTestCacheRedis(t, CacheConfig{TTL: time.Minute, Namespace: "test:cache"}, mr)
	h := mw(backend)

	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec1.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("first X-Cache = %q, want MISS", rec1.Header().Get("X-Cache"))
	}

	// Second middleware instance sharing the same Redis sees the HIT.
	mw2, _ := newTestCacheRedis(t, CacheConfig{TTL: time.Minute, Namespace: "test:cache"}, mr)
	rec2 := httptest.NewRecorder()
	mw2(backend).ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec2.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("second instance X-Cache = %q, want HIT", rec2.Header().Get("X-Cache"))
	}
	if rec2.Body.String() != "shared" {
		t.Fatalf("body = %q", rec2.Body.String())
	}
	if calls.Load() != 1 {
		t.Fatalf("backend calls = %d, want 1", calls.Load())
	}
}

func TestRedisCacheTTLExpiry(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)
	var calls atomic.Int64
	backend := countingBackend(&calls, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("v"))
	})

	mw, _ := newTestCacheRedis(t, CacheConfig{TTL: 2 * time.Second, Namespace: "ttl"}, mr)
	h := mw(backend)

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))
	mr.FastForward(3 * time.Second)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("after expiry X-Cache = %q, want MISS", rec.Header().Get("X-Cache"))
	}
	if calls.Load() != 2 {
		t.Fatalf("backend calls = %d, want 2", calls.Load())
	}
}

func TestRedisCacheVarySeparatesEntries(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)
	var calls atomic.Int64
	backend := countingBackend(&calls, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.Header.Get("Accept-Encoding")))
	})

	mw, _ := newTestCacheRedis(t, CacheConfig{
		TTL:       time.Minute,
		Vary:      []string{"Accept-Encoding"},
		Namespace: "vary",
	}, mr)
	h := mw(backend)

	req1 := httptest.NewRequest(http.MethodGet, "/x", nil)
	req1.Header.Set("Accept-Encoding", "gzip")
	h.ServeHTTP(httptest.NewRecorder(), req1)

	req2 := httptest.NewRequest(http.MethodGet, "/x", nil)
	req2.Header.Set("Accept-Encoding", "br")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)

	if calls.Load() != 2 {
		t.Fatalf("backend calls = %d, want 2", calls.Load())
	}
	if rec2.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("second variant X-Cache = %q, want MISS", rec2.Header().Get("X-Cache"))
	}
}

func TestRedisCachePurgeInvalidates(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)
	var calls atomic.Int64
	backend := countingBackend(&calls, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("v"))
	})

	mw, _ := newTestCacheRedis(t, CacheConfig{TTL: time.Minute, Namespace: "purge"}, mr)
	h := mw(backend)

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))

	purge := httptest.NewRecorder()
	h.ServeHTTP(purge, httptest.NewRequest("PURGE", "/x", nil))
	if purge.Code != http.StatusOK {
		t.Fatalf("PURGE status = %d", purge.Code)
	}
	if purge.Header().Get("X-Cache") != "PURGED" {
		t.Fatalf("PURGE X-Cache = %q, want PURGED", purge.Header().Get("X-Cache"))
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("after PURGE X-Cache = %q, want MISS", rec.Header().Get("X-Cache"))
	}
	if calls.Load() != 2 {
		t.Fatalf("backend calls = %d, want 2", calls.Load())
	}
}

func TestRedisCacheInvalidateAll(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	store := newCacheRedisStoreFromClient(client, nil, "inv", 0, 0, time.Now)

	now := time.Now()
	_ = store.Set("a", &cachedResponse{status: 200, body: []byte("a"), storedAt: now, expiresAt: now.Add(time.Hour)})
	_ = store.Set("b", &cachedResponse{status: 200, body: []byte("b"), storedAt: now, expiresAt: now.Add(time.Hour)})
	if err := store.InvalidateAll(); err != nil {
		t.Fatalf("InvalidateAll() error = %v", err)
	}
	if got, err := store.Get("a"); err != nil || got != nil {
		t.Fatalf("expected a invalidated, got %#v err=%v", got, err)
	}
	if got, err := store.Get("b"); err != nil || got != nil {
		t.Fatalf("expected b invalidated, got %#v err=%v", got, err)
	}
}

func TestRedisCacheFailClosedOnUnavailable(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	store := newCacheRedisStoreFromClient(client, client, "down", 50*time.Millisecond, 0, time.Now)
	mr.Close()

	mw, closer, err := NewCache(CacheConfig{
		TTL:          time.Minute,
		Store:        "redis",
		FailOpen:     false,
		StoreBackend: store,
	})
	if err != nil {
		t.Fatalf("NewCache() error = %v", err)
	}
	t.Cleanup(func() { _ = closer.Close() })

	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (fail closed)", rec.Code)
	}
}

func TestRedisCacheFailOpenBypassesOnUnavailable(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	store := newCacheRedisStoreFromClient(client, client, "open", 50*time.Millisecond, 0, time.Now)
	mr.Close()

	var calls atomic.Int64
	mw, closer, err := NewCache(CacheConfig{
		TTL:          time.Minute,
		Store:        "redis",
		FailOpen:     true,
		StoreBackend: store,
	})
	if err != nil {
		t.Fatalf("NewCache() error = %v", err)
	}
	t.Cleanup(func() { _ = closer.Close() })

	h := mw(countingBackend(&calls, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (fail open)", rec.Code)
	}
	if rec.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("X-Cache = %q, want MISS", rec.Header().Get("X-Cache"))
	}
	if calls.Load() != 1 {
		t.Fatalf("backend calls = %d, want 1", calls.Load())
	}
}

func TestRedisCacheRequiresURL(t *testing.T) {
	t.Parallel()

	_, _, err := NewCache(CacheConfig{Store: "redis"})
	if err == nil {
		t.Fatal("expected error for missing redis_url")
	}
}

func TestRedisCacheRespectsMaxObjectBytes(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)
	var calls atomic.Int64
	big := make([]byte, 2048)
	backend := countingBackend(&calls, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(big)
	})

	mw, _ := newTestCacheRedis(t, CacheConfig{
		TTL:            time.Minute,
		MaxObjectBytes: 1024,
		Namespace:      "big",
	}, mr)
	h := mw(backend)

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))
	if calls.Load() != 2 {
		t.Fatalf("backend calls = %d, want 2 (oversized body must not be cached)", calls.Load())
	}
}

func TestCacheMemoryInvalidateAll(t *testing.T) {
	t.Parallel()

	store := newCacheMemoryStore(10, time.Now)
	now := time.Now()
	_ = store.Set("a", &cachedResponse{status: 200, body: []byte("a"), storedAt: now, expiresAt: now.Add(time.Hour)})
	if err := store.InvalidateAll(); err != nil {
		t.Fatalf("InvalidateAll() error = %v", err)
	}
	if store.len() != 0 {
		t.Fatalf("len = %d, want 0", store.len())
	}
}
