package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimitUnderLimitPasses(t *testing.T) {
	t.Parallel()

	mw := mustRateLimit(t, RateLimitConfig{
		Strategy: SlidingWindow,
		Limit:    2,
		Window:   100 * time.Millisecond,
		By:       "ip",
	})

	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), mw)

	req := httptest.NewRequest(http.MethodGet, "/orders", nil)
	req.RemoteAddr = "10.0.0.10:1234"

	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d status = %d, want %d", i+1, rec.Code, http.StatusOK)
		}
	}
}

func TestRateLimitOverLimitReturns429(t *testing.T) {
	t.Parallel()

	mw := mustRateLimit(t, RateLimitConfig{
		Strategy: SlidingWindow,
		Limit:    1,
		Window:   time.Second,
		By:       "ip",
	})

	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), mw)

	req := httptest.NewRequest(http.MethodGet, "/orders", nil)
	req.RemoteAddr = "10.0.0.11:1234"

	first := httptest.NewRecorder()
	handler.ServeHTTP(first, req)
	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d, want %d", first.Code, http.StatusOK)
	}

	second := httptest.NewRecorder()
	handler.ServeHTTP(second, req)
	assertRateLimitedBody(t, second)
}

func TestRateLimitWindowExpirationAllowsAgain(t *testing.T) {
	t.Parallel()

	mw := mustRateLimit(t, RateLimitConfig{
		Strategy: SlidingWindow,
		Limit:    1,
		Window:   40 * time.Millisecond,
		By:       "route",
	})

	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), mw)

	req := httptest.NewRequest(http.MethodGet, "/orders", nil)

	first := httptest.NewRecorder()
	handler.ServeHTTP(first, req)
	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d, want %d", first.Code, http.StatusOK)
	}

	second := httptest.NewRecorder()
	handler.ServeHTTP(second, req)
	assertRateLimitedBody(t, second)

	time.Sleep(60 * time.Millisecond)

	third := httptest.NewRecorder()
	handler.ServeHTTP(third, req)
	if third.Code != http.StatusOK {
		t.Fatalf("third status = %d, want %d", third.Code, http.StatusOK)
	}
}

func mustRateLimit(t *testing.T, cfg RateLimitConfig) Middleware {
	t.Helper()
	mw, err := NewRateLimit(cfg)
	if err != nil {
		t.Fatalf("NewRateLimit() error = %v", err)
	}
	return mw
}

func assertRateLimitedBody(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusTooManyRequests)
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if body["error"] != "rate_limited" {
		t.Fatalf("error = %q, want rate_limited", body["error"])
	}
	if body["status"] != "error" {
		t.Fatalf("status = %q, want error", body["status"])
	}
}
