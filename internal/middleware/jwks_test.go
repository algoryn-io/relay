package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type fakeJWKSClock struct {
	now time.Time
}

func (c *fakeJWKSClock) Now() time.Time {
	return c.now
}

func (c *fakeJWKSClock) Advance(d time.Duration) {
	c.now = c.now.Add(d)
}

type rotatingJWKSEndpoint struct {
	mu      sync.Mutex
	keys    []*rsaKidPair
	fail    bool
	fetches int
}

func (e *rotatingJWKSEndpoint) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.fetches++
	if e.fail {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	_ = json.NewEncoder(w).Encode(buildJWKS(e.keys))
}

func (e *rotatingJWKSEndpoint) setKeys(keys ...*rsaKidPair) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.keys = keys
}

func (e *rotatingJWKSEndpoint) setFailure(fail bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.fail = fail
}

func (e *rotatingJWKSEndpoint) fetchCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.fetches
}

func TestJWKSRotationRevokesMissingKeyByDefault(t *testing.T) {
	key1, _ := rsaKeyFixture(t)
	key2, _ := rsaKeyFixture(t)
	endpoint := &rotatingJWKSEndpoint{
		keys: []*rsaKidPair{{kid: "key-1", priv: key1}},
	}
	server := httptest.NewTLSServer(endpoint)
	t.Cleanup(server.Close)

	clock := &fakeJWKSClock{now: time.Unix(1_700_000_000, 0)}
	cache := newJWKSCache(server.URL, time.Minute, 0, server.Client())
	cache.now = clock.Now

	if _, err := cache.getKey("key-1"); err != nil {
		t.Fatalf("prime key-1: %v", err)
	}
	if _, err := cache.getKey("key-1"); err != nil {
		t.Fatalf("cached key-1: %v", err)
	}
	if got := endpoint.fetchCount(); got != 1 {
		t.Fatalf("fresh cache fetches = %d, want 1", got)
	}

	// Rotation becomes visible when the independent refresh TTL expires.
	endpoint.setKeys(&rsaKidPair{kid: "key-2", priv: key2})
	clock.Advance(time.Minute + time.Second)
	if _, err := cache.getKey("key-2"); err != nil {
		t.Fatalf("rotated key-2: %v", err)
	}
	if _, err := cache.getKey("key-1"); err == nil {
		t.Fatal("removed key-1 remained accepted with zero stale grace")
	}
}

func TestJWKSRetiredKeyGraceExpiresFromRemoval(t *testing.T) {
	key1, _ := rsaKeyFixture(t)
	key2, _ := rsaKeyFixture(t)
	endpoint := &rotatingJWKSEndpoint{
		keys: []*rsaKidPair{{kid: "key-1", priv: key1}},
	}
	server := httptest.NewTLSServer(endpoint)
	t.Cleanup(server.Close)

	const grace = 10 * time.Minute
	clock := &fakeJWKSClock{now: time.Unix(1_700_000_000, 0)}
	cache := newJWKSCache(server.URL, time.Minute, grace, server.Client())
	cache.now = clock.Now

	if _, err := cache.getKey("key-1"); err != nil {
		t.Fatalf("prime key-1: %v", err)
	}
	endpoint.setKeys(&rsaKidPair{kid: "key-2", priv: key2})
	clock.Advance(time.Minute + time.Second)
	if _, err := cache.getKey("key-2"); err != nil {
		t.Fatalf("refresh key-2: %v", err)
	}

	clock.Advance(grace - time.Second)
	if _, err := cache.getKey("key-1"); err != nil {
		t.Fatalf("retired key within grace: %v", err)
	}
	clock.Advance(2 * time.Second)
	if _, err := cache.getKey("key-1"); err == nil {
		t.Fatal("retired key remained accepted after grace expiration")
	}
}

func TestJWKSRefreshFailureUsesLastSuccessfulRefreshBound(t *testing.T) {
	key1, _ := rsaKeyFixture(t)
	endpoint := &rotatingJWKSEndpoint{
		keys: []*rsaKidPair{{kid: "key-1", priv: key1}},
	}
	server := httptest.NewTLSServer(endpoint)
	t.Cleanup(server.Close)

	const (
		ttl   = time.Minute
		grace = 5 * time.Minute
	)
	clock := &fakeJWKSClock{now: time.Unix(1_700_000_000, 0)}
	cache := newJWKSCache(server.URL, ttl, grace, server.Client())
	cache.now = clock.Now

	if _, err := cache.getKey("key-1"); err != nil {
		t.Fatalf("prime key-1: %v", err)
	}
	lastSuccess := cache.lastSuccessfulRefresh
	endpoint.setFailure(true)

	clock.Advance(ttl + time.Second)
	if _, err := cache.getKey("key-1"); err != nil {
		t.Fatalf("stale key within bounded grace: %v", err)
	}
	if !cache.lastSuccessfulRefresh.Equal(lastSuccess) {
		t.Fatal("failed refresh advanced lastSuccessfulRefresh")
	}

	clock.Advance(grace)
	if _, err := cache.getKey("key-1"); err == nil {
		t.Fatal("network failures prolonged stale key beyond TTL plus grace")
	}
	if _, err := cache.getKey("key-1"); err == nil {
		t.Fatal("repeated refresh failure reset the stale acceptance bound")
	}
}

func TestJWKSRefreshFailureFailsClosedWithoutGrace(t *testing.T) {
	key1, _ := rsaKeyFixture(t)
	endpoint := &rotatingJWKSEndpoint{
		keys: []*rsaKidPair{{kid: "key-1", priv: key1}},
	}
	server := httptest.NewTLSServer(endpoint)
	t.Cleanup(server.Close)

	clock := &fakeJWKSClock{now: time.Unix(1_700_000_000, 0)}
	cache := newJWKSCache(server.URL, time.Minute, 0, server.Client())
	cache.now = clock.Now

	if _, err := cache.getKey("key-1"); err != nil {
		t.Fatalf("prime key-1: %v", err)
	}
	endpoint.setFailure(true)
	clock.Advance(time.Minute + time.Second)
	if _, err := cache.getKey("key-1"); err == nil {
		t.Fatal("stale key accepted after refresh failure with zero grace")
	}
}
