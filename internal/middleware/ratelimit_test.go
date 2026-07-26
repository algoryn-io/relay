package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestRateLimitAPIKeyHashesMapKey(t *testing.T) {
	t.Parallel()

	store, err := newMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	rl := &rateLimiter{
		limit:  2,
		window: time.Minute,
		by:     "api_key",
		header: "X-API-Key",
		store:  store,
	}

	req := httptest.NewRequest(http.MethodGet, "/orders", nil)
	req.Header.Set("X-API-Key", "plain-api-key")

	key := rl.keyFromRequest(req)
	if key == "" {
		t.Fatal("keyFromRequest() = empty, want hashed value")
	}
	if key == "plain-api-key" {
		t.Fatal("keyFromRequest() returned raw API key")
	}
	if len(key) != 64 {
		t.Fatalf("len(key) = %d, want 64", len(key))
	}
	// Verify the key ends up in the bucket (not the raw value).
	allowed, _, _, _ := store.Check(context.Background(), key, 2, time.Minute, time.Now())
	if !allowed {
		t.Fatal("Check() = false, want true")
	}
	if store.hasBucket("plain-api-key") {
		t.Fatal("buckets contains raw API key")
	}
	if !store.hasBucket(key) {
		t.Fatal("buckets missing hashed API key")
	}
}

func TestRateLimitCapsTimestampSliceAtLimit(t *testing.T) {
	t.Parallel()

	store, err := newMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	store.seedBucket("client", []time.Time{
		now.Add(-3 * time.Second),
		now.Add(-2 * time.Second),
		now.Add(-1 * time.Second),
	})

	allowed, _, _, _ := store.Check(context.Background(), "client", 2, time.Minute, now)
	if allowed {
		t.Fatal("Check() = true, want false")
	}
	if got := store.bucketLen("client"); got != 2 {
		t.Fatalf("len(bucket) = %d, want 2", got)
	}
}

func TestRateLimitAuthenticatedIdentityCannotBeSpoofedByHeader(t *testing.T) {
	t.Parallel()

	auth, err := NewAPIKey(APIKeyConfig{Keys: map[string]string{"secret": "caller-1"}})
	if err != nil {
		t.Fatal(err)
	}
	limit := mustRateLimit(t, RateLimitConfig{
		Limit:  1,
		Window: time.Minute,
		Key: RateLimitKeyConfig{
			Selectors:     []RateLimitSelector{{Type: "identity"}},
			RejectMissing: true,
		},
	})
	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), auth, limit)

	first := httptest.NewRequest(http.MethodGet, "/", nil)
	first.Header.Set("X-API-Key", "secret")
	first.Header.Set(defaultSubjectHeader, "spoof-a")
	handler.ServeHTTP(httptest.NewRecorder(), first)

	second := httptest.NewRequest(http.MethodGet, "/", nil)
	second.Header.Set("X-API-Key", "secret")
	second.Header.Set(defaultSubjectHeader, "spoof-b")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, second)
	assertRateLimitedBody(t, rec)
}

func TestRateLimitCompositeKeyIsOrderedBoundedAndPrivate(t *testing.T) {
	t.Parallel()

	store, err := newMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	cfg := RateLimitConfig{
		Limit: 1, Window: time.Minute,
		Key: RateLimitKeyConfig{
			Namespace: "orders",
			Selectors: []RateLimitSelector{
				{Type: "route"},
				{Type: "header", Name: "X-Plan"},
			},
		},
	}
	_, err = newRateLimitWithStore(cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	rl := &rateLimiter{
		namespace: "orders",
		selectors: []RateLimitSelector{
			{Type: "route"},
			{Type: "header", Name: "X-Plan"},
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/private/customer-123", nil)
	req.Header.Set("X-Plan", "enterprise-customer-456")
	key, complete := rl.rateLimitKey(req)
	if !complete {
		t.Fatal("composite key unexpectedly incomplete")
	}
	if strings.Contains(key, "customer-123") || strings.Contains(key, "customer-456") {
		t.Fatalf("key leaked source values: %q", key)
	}
	if got, want := len(key), len("orders:")+64; got != want {
		t.Fatalf("key length = %d, want %d", got, want)
	}

	rl.selectors[0], rl.selectors[1] = rl.selectors[1], rl.selectors[0]
	reordered, _ := rl.rateLimitKey(req)
	if reordered == key {
		t.Fatal("selector order did not affect the composite key")
	}
}

func TestRateLimitMissingSelectorRejectsOrFallsBack(t *testing.T) {
	t.Parallel()

	reject := mustRateLimit(t, RateLimitConfig{
		Limit: 1, Window: time.Minute,
		Key: RateLimitKeyConfig{
			Selectors:     []RateLimitSelector{{Type: "tenant"}},
			RejectMissing: true,
		},
	})
	handler := reject(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing selector status = %d, want 400", rec.Code)
	}

	fallback := RateLimitSelector{Type: "ip"}
	rl := &rateLimiter{
		namespace: "relay:ratelimit:v1",
		selectors: []RateLimitSelector{{Type: "tenant"}},
		fallback:  &fallback,
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.0.2.10:1234"
	if _, complete := rl.rateLimitKey(req); !complete {
		t.Fatal("configured IP fallback was not used")
	}
}

func TestRateLimitVerifiedJWTClaimIgnoresClientHeaders(t *testing.T) {
	t.Parallel()

	rl := &rateLimiter{
		namespace: "claims",
		selectors: []RateLimitSelector{{
			Type: "claim", Claim: "account_id",
		}},
	}
	requestWithClaim := func(claim, spoof string) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Account-Id", spoof)
		return withAuthIdentity(req, AuthIdentity{
			Source: "jwt",
			Claims: map[string]string{"account_id": claim},
		})
	}
	first, complete := rl.rateLimitKey(requestWithClaim("verified-a", "spoof"))
	if !complete {
		t.Fatal("verified claim was not selected")
	}
	second, _ := rl.rateLimitKey(requestWithClaim("verified-a", "different-spoof"))
	if first != second {
		t.Fatal("client header changed a verified claim key")
	}
	third, _ := rl.rateLimitKey(requestWithClaim("verified-b", "spoof"))
	if first == third {
		t.Fatal("different verified claims shared a key")
	}
}

func TestRateLimitJWTClaimAliasAndExtAuthzClaims(t *testing.T) {
	t.Parallel()

	alias, err := normalizeRateLimitSelector(RateLimitSelector{Type: "jwt_claim", Claim: "account_id"})
	if err != nil {
		t.Fatal(err)
	}
	if alias.Type != "claim" || alias.Claim != "account_id" {
		t.Fatalf("jwt_claim alias = %+v", alias)
	}

	rl := &rateLimiter{
		namespace: "claims",
		selectors: []RateLimitSelector{alias},
	}
	req := withAuthIdentity(httptest.NewRequest(http.MethodGet, "/", nil), AuthIdentity{
		Source: "ext_authz",
		Claims: map[string]string{"account_id": "acct-1"},
	})
	if _, complete := rl.rateLimitKey(req); !complete {
		t.Fatal("ext_authz claim was not selectable")
	}
}

func TestWithAuthIdentityStripsClientRelayAuthHeaders(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(extAuthzSubjectHeader, "spoof")
	req.Header.Set(extAuthzClaimHeaderPrefix+"Role", "admin")
	out := withAuthIdentity(req, AuthIdentity{Source: "api_key", KeyID: "k1"})
	if got := out.Header.Get(extAuthzSubjectHeader); got != "" {
		t.Fatalf("spoofed subject header survived: %q", got)
	}
	if got := out.Header.Get(extAuthzClaimHeaderPrefix + "Role"); got != "" {
		t.Fatalf("spoofed claim header survived: %q", got)
	}
	identity, ok := authIdentityFromRequest(out)
	if !ok || identity.KeyID != "k1" {
		t.Fatalf("identity = %+v ok=%v", identity, ok)
	}
}

func mustRateLimit(t *testing.T, cfg RateLimitConfig) Middleware {
	t.Helper()
	mw, closer, err := NewRateLimit(cfg)
	if err != nil {
		t.Fatalf("NewRateLimit() error = %v", err)
	}
	if closer != nil {
		t.Cleanup(func() { _ = closer.Close() })
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
