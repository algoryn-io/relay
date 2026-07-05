package middleware

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// countingBackend returns a handler that increments a counter per call and lets
// the test control the response.
func countingBackend(count *atomic.Int64, fn func(w http.ResponseWriter, r *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		fn(w, r)
	})
}

func newTestCache(t *testing.T, cfg CacheConfig) Middleware {
	t.Helper()
	mw, _, err := NewCache(cfg)
	if err != nil {
		t.Fatalf("NewCache() error = %v", err)
	}
	return mw
}

func TestCacheHitAvoidsSecondBackendCall(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	backend := countingBackend(&calls, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello"))
	})

	mw := newTestCache(t, CacheConfig{TTL: time.Minute})
	h := mw(backend)

	// First request: MISS, backend called.
	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec1.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("first X-Cache = %q, want MISS", rec1.Header().Get("X-Cache"))
	}
	if rec1.Body.String() != "hello" {
		t.Fatalf("first body = %q", rec1.Body.String())
	}

	// Second request: HIT, backend not called again.
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec2.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("second X-Cache = %q, want HIT", rec2.Header().Get("X-Cache"))
	}
	if rec2.Body.String() != "hello" {
		t.Fatalf("second body = %q", rec2.Body.String())
	}
	if rec2.Header().Get("Content-Type") != "text/plain" {
		t.Fatalf("cached Content-Type not replayed: %q", rec2.Header().Get("Content-Type"))
	}
	if calls.Load() != 1 {
		t.Fatalf("backend calls = %d, want 1", calls.Load())
	}
}

func TestCacheExpiryTriggersRefetch(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	backend := countingBackend(&calls, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("v"))
	})

	now := time.Unix(1_000_000, 0)
	clock := func() time.Time { return now }

	mw := newTestCache(t, CacheConfig{TTL: 10 * time.Second, Now: clock})
	h := mw(backend)

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))
	// Advance past the TTL.
	now = now.Add(11 * time.Second)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("after expiry X-Cache = %q, want MISS", rec.Header().Get("X-Cache"))
	}
	if calls.Load() != 2 {
		t.Fatalf("backend calls = %d, want 2", calls.Load())
	}
}

func TestCacheRespectsNoStoreResponse(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	backend := countingBackend(&calls, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte("secret"))
	})

	mw := newTestCache(t, CacheConfig{TTL: time.Minute})
	h := mw(backend)

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))
	if calls.Load() != 2 {
		t.Fatalf("backend calls = %d, want 2 (no-store must not cache)", calls.Load())
	}
}

func TestCacheHonorsResponseMaxAge(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	backend := countingBackend(&calls, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=5")
		_, _ = w.Write([]byte("v"))
	})

	now := time.Unix(2_000_000, 0)
	mw := newTestCache(t, CacheConfig{TTL: time.Hour, Now: func() time.Time { return now }})
	h := mw(backend)

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))
	// Within max-age: HIT.
	now = now.Add(3 * time.Second)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("within max-age X-Cache = %q, want HIT", rec.Header().Get("X-Cache"))
	}
	// Past max-age (overrides the longer configured TTL): MISS.
	now = now.Add(3 * time.Second)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("past max-age X-Cache = %q, want MISS", rec.Header().Get("X-Cache"))
	}
}

func TestCacheBypassesNonCacheableMethod(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	backend := countingBackend(&calls, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	mw := newTestCache(t, CacheConfig{TTL: time.Minute})
	h := mw(backend)

	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/x", nil))
		if rec.Header().Get("X-Cache") != "BYPASS" {
			t.Fatalf("POST X-Cache = %q, want BYPASS", rec.Header().Get("X-Cache"))
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("backend calls = %d, want 2", calls.Load())
	}
}

func TestCacheDoesNotStoreLargeBodies(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	big := make([]byte, 2048)
	backend := countingBackend(&calls, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(big)
	})

	mw := newTestCache(t, CacheConfig{TTL: time.Minute, MaxObjectBytes: 1024})
	h := mw(backend)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Body.Len() != 2048 {
		t.Fatalf("body len = %d, want 2048 (must still stream through)", rec.Body.Len())
	}
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))
	if calls.Load() != 2 {
		t.Fatalf("backend calls = %d, want 2 (oversized body must not be cached)", calls.Load())
	}
}

func TestCacheVarySeparatesEntries(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	backend := countingBackend(&calls, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.Header.Get("Accept-Encoding")))
	})

	mw := newTestCache(t, CacheConfig{TTL: time.Minute, Vary: []string{"Accept-Encoding"}})
	h := mw(backend)

	req1 := httptest.NewRequest(http.MethodGet, "/x", nil)
	req1.Header.Set("Accept-Encoding", "gzip")
	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, req1)

	req2 := httptest.NewRequest(http.MethodGet, "/x", nil)
	req2.Header.Set("Accept-Encoding", "br")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)

	if calls.Load() != 2 {
		t.Fatalf("backend calls = %d, want 2 (Vary must separate entries)", calls.Load())
	}
	if rec2.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("second variant X-Cache = %q, want MISS", rec2.Header().Get("X-Cache"))
	}
}

func TestCacheLRUEviction(t *testing.T) {
	t.Parallel()

	store := newCacheMemoryStore(2, time.Now)
	mk := func(id string) *cachedResponse {
		return &cachedResponse{status: 200, body: []byte(id), storedAt: time.Now(), expiresAt: time.Now().Add(time.Hour)}
	}
	store.Set("a", mk("a"))
	store.Set("b", mk("b"))
	_, _ = store.Get("a") // make "a" most-recently-used
	store.Set("c", mk("c")) // should evict "b"

	if _, ok := store.Get("b"); ok {
		t.Fatal("expected b to be evicted")
	}
	if _, ok := store.Get("a"); !ok {
		t.Fatal("expected a to survive")
	}
	if store.len() != 2 {
		t.Fatalf("store len = %d, want 2", store.len())
	}
}

func TestCacheAgeHeader(t *testing.T) {
	t.Parallel()

	now := time.Unix(3_000_000, 0)
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("v"))
	})
	mw := newTestCache(t, CacheConfig{TTL: time.Hour, Now: func() time.Time { return now }})
	h := mw(backend)

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))
	now = now.Add(42 * time.Second)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if got := rec.Header().Get("Age"); got != strconv.Itoa(42) {
		t.Fatalf("Age = %q, want 42", got)
	}
}
