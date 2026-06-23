package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newTestRateLimitRedis(t *testing.T, cfg RateLimitConfig, mr *miniredis.Miniredis) Middleware {
	t.Helper()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	store := newRedisStoreFromClient(client)
	mw, err := newRateLimitWithStore(cfg, store)
	if err != nil {
		t.Fatalf("newRateLimitWithStore: %v", err)
	}
	return mw
}

// TestRedisRateLimitUnderLimitPasses verifies that requests within the limit
// are allowed when the Redis store is in use.
func TestRedisRateLimitUnderLimitPasses(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)
	mw := newTestRateLimitRedis(t, RateLimitConfig{
		Strategy: SlidingWindow,
		Limit:    3,
		Window:   time.Minute,
		By:       "ip",
	}, mr)

	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), mw)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.1.2.3:9000"

	for i := 0; i < 3; i++ {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i+1, rr.Code)
		}
	}
}

// TestRedisRateLimitOverLimitReturns429 verifies that exceeding the limit
// returns 429 when the Redis store is in use.
func TestRedisRateLimitOverLimitReturns429(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)
	mw := newTestRateLimitRedis(t, RateLimitConfig{
		Strategy: SlidingWindow,
		Limit:    2,
		Window:   time.Minute,
		By:       "ip",
	}, mr)

	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), mw)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.2.3.4:9000"

	for i := 0; i < 2; i++ {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i+1, rr.Code)
		}
	}

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assertRateLimitedBody(t, rr)
}

// TestRedisRateLimitWindowExpirationAllowsAgain verifies that after the window
// expires, new requests are allowed.
func TestRedisRateLimitWindowExpirationAllowsAgain(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)
	window := 50 * time.Millisecond
	mw := newTestRateLimitRedis(t, RateLimitConfig{
		Strategy: SlidingWindow,
		Limit:    1,
		Window:   window,
		By:       "route",
	}, mr)

	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), mw)

	req := httptest.NewRequest(http.MethodGet, "/items", nil)

	first := httptest.NewRecorder()
	handler.ServeHTTP(first, req)
	if first.Code != http.StatusOK {
		t.Fatalf("first: status = %d, want 200", first.Code)
	}

	second := httptest.NewRecorder()
	handler.ServeHTTP(second, req)
	assertRateLimitedBody(t, second)

	// Fast-forward miniredis clock past the window.
	mr.FastForward(window + 10*time.Millisecond)

	third := httptest.NewRecorder()
	handler.ServeHTTP(third, req)
	if third.Code != http.StatusOK {
		t.Fatalf("after window expiry: status = %d, want 200", third.Code)
	}
}

// TestRedisRateLimitIsolatesClientsByIP verifies that two different IPs have
// independent counters.
func TestRedisRateLimitIsolatesClientsByIP(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)
	mw := newTestRateLimitRedis(t, RateLimitConfig{
		Strategy: SlidingWindow,
		Limit:    1,
		Window:   time.Minute,
		By:       "ip",
	}, mr)

	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), mw)

	makeReq := func(ip string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = ip + ":9000"
		return r
	}

	// First request from each IP should be allowed.
	for _, ip := range []string{"10.0.0.1", "10.0.0.2"} {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, makeReq(ip))
		if rr.Code != http.StatusOK {
			t.Errorf("ip %s: first request status = %d, want 200", ip, rr.Code)
		}
	}

	// Second request from first IP should be rejected; second IP still ok
	// (it has its own bucket and hasn't been exhausted here because of
	// the limit=1 — first IP exhausted, second IP also exhausted).
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, makeReq("10.0.0.1"))
	assertRateLimitedBody(t, rr)
}

// TestRedisRateLimitAPIKeyHashIsConsistent verifies that two stores (simulating
// different relay instances) produce the same bucket key for the same API key.
func TestRedisRateLimitAPIKeyHashIsConsistent(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)
	store1 := newTestRedisStoreHelper(t, mr)
	store2 := newTestRedisStoreHelper(t, mr)

	apiKey := "sk-shared-key-across-instances"
	h1 := store1.HashKey(apiKey)
	h2 := store2.HashKey(apiKey)

	if h1 != h2 {
		t.Errorf("HashKey mismatch: store1=%q store2=%q — distributed buckets would diverge", h1, h2)
	}
	if h1 == apiKey {
		t.Error("HashKey returned the raw API key")
	}
}

// TestRedisRateLimitFailOpen verifies that when Redis is unavailable, requests
// are allowed (fail-open behavior).
func TestRedisRateLimitFailOpen(t *testing.T) {
	t.Parallel()

	// Start miniredis, then close it immediately to simulate unavailability.
	mr := miniredis.RunT(t)
	addr := mr.Addr()
	mr.Close()

	client := redis.NewClient(&redis.Options{
		Addr:       addr,
		MaxRetries: 0, // no retries so the test stays fast
	})
	store := newRedisStoreFromClient(client)

	mw, err := newRateLimitWithStore(RateLimitConfig{
		Limit:  1,
		Window: time.Minute,
		By:     "ip",
	}, store)
	if err != nil {
		t.Fatal(err)
	}

	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), mw)

	// Multiple requests should all pass because fail-open allows them.
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("request %d: status = %d, want 200 (fail-open)", i+1, rr.Code)
		}
	}
}

// TestRedisRateLimitRateLimitHeaders verifies that X-RateLimit-* headers are
// set correctly when using the Redis store.
func TestRedisRateLimitRateLimitHeaders(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)
	mw := newTestRateLimitRedis(t, RateLimitConfig{
		Strategy: SlidingWindow,
		Limit:    5,
		Window:   time.Minute,
		By:       "ip",
	}, mr)

	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), mw)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.9.8.7:1234"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if h := rr.Header().Get("X-RateLimit-Limit"); h != "5" {
		t.Errorf("X-RateLimit-Limit = %q, want 5", h)
	}
	if h := rr.Header().Get("X-RateLimit-Remaining"); h == "" {
		t.Error("X-RateLimit-Remaining is empty")
	}
	if h := rr.Header().Get("X-RateLimit-Reset"); h == "" {
		t.Error("X-RateLimit-Reset is empty")
	}
}

// TestNewRateLimitRedisStoreURLRequired verifies that NewRateLimit returns an
// error when store=redis but no URL is provided.
func TestNewRateLimitRedisStoreURLRequired(t *testing.T) {
	t.Parallel()

	_, _, err := NewRateLimit(RateLimitConfig{
		Strategy: SlidingWindow,
		Limit:    10,
		Window:   time.Minute,
		By:       "ip",
		Store:    "redis",
		RedisURL: "", // missing
	})
	if err == nil {
		t.Error("expected error for missing redis_url, got nil")
	}
}

func newTestRedisStoreHelper(t *testing.T, mr *miniredis.Miniredis) *redisStore {
	t.Helper()
	return newRedisStoreFromClient(redis.NewClient(&redis.Options{Addr: mr.Addr()}))
}
