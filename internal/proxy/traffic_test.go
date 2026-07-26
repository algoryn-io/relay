package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"algoryn.io/relay/internal/config"
)

func TestTrafficBucketDeterministic(t *testing.T) {
	t.Parallel()
	a := trafficBucket("user-42")
	b := trafficBucket("user-42")
	if a != b {
		t.Fatalf("bucket not stable: %d vs %d", a, b)
	}
	if a < 0 || a > 99 {
		t.Fatalf("bucket out of range: %d", a)
	}
}

func TestCanaryPercentDeterministic(t *testing.T) {
	t.Parallel()

	stable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Backend", "stable")
		w.WriteHeader(http.StatusOK)
	}))
	defer stable.Close()
	canary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Backend", "canary")
		w.WriteHeader(http.StatusOK)
	}))
	defer canary.Close()

	p := newTestProxy(t, map[string]config.BackendRuntime{
		"stable": {Name: "stable", Strategy: "round_robin", Instances: []config.InstanceRuntime{{URL: stable.URL}}},
		"canary": {Name: "canary", Strategy: "round_robin", Instances: []config.InstanceRuntime{{URL: canary.URL}}},
	})

	route := &config.RouteRuntime{
		Name:        "api",
		BackendName: "stable",
		Traffic: &config.RouteTrafficRuntime{
			Canary: &config.RouteCanaryRuntime{
				Backend:   "canary",
				Percent:   100,
				KeyHeader: "X-User-Id",
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Header.Set("X-User-Id", "same-user")
	req.RemoteAddr = "203.0.113.10:1"
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req, route)
	if got := rec.Header().Get("X-Backend"); got != "canary" {
		t.Fatalf("percent=100 backend = %q, want canary", got)
	}

	route.Traffic.Canary.Percent = 0
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, req, route)
	if got := rec.Header().Get("X-Backend"); got != "stable" {
		t.Fatalf("percent=0 backend = %q, want stable", got)
	}

	// Same key always lands on the same side for a fixed percent.
	route.Traffic.Canary.Percent = 50
	var first string
	for i := 0; i < 20; i++ {
		rec = httptest.NewRecorder()
		p.ServeHTTP(rec, req, route)
		got := rec.Header().Get("X-Backend")
		if first == "" {
			first = got
		} else if got != first {
			t.Fatalf("same key flipped backend: %q then %q", first, got)
		}
	}
}

func TestStickySessionCookieAffinity(t *testing.T) {
	t.Parallel()

	var hits1, hits2 atomic.Int64
	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits1.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv1.Close()
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits2.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv2.Close()

	p := newTestProxy(t, map[string]config.BackendRuntime{
		"b": {
			Name:     "b",
			Strategy: "round_robin",
			Instances: []config.InstanceRuntime{
				{URL: srv1.URL},
				{URL: srv2.URL},
			},
		},
	})

	route := &config.RouteRuntime{
		Name:        "r",
		BackendName: "b",
		Traffic: &config.RouteTrafficRuntime{
			Sticky: &config.RouteStickyRuntime{
				Cookie:     "relay_affinity",
				CookiePath: "/",
				CookieTTL:  time.Hour,
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.RemoteAddr = "203.0.113.10:1"
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req, route)
	resp := rec.Result()
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected sticky Set-Cookie")
	}
	sticky := cookies[0]
	if sticky.Name != "relay_affinity" || sticky.Value == "" {
		t.Fatalf("unexpected cookie: %+v", sticky)
	}

	hits1.Store(0)
	hits2.Store(0)
	for i := 0; i < 10; i++ {
		req = httptest.NewRequest(http.MethodGet, "/x", nil)
		req.RemoteAddr = "203.0.113.10:1"
		req.AddCookie(sticky)
		rec = httptest.NewRecorder()
		p.ServeHTTP(rec, req, route)
	}
	if hits1.Load() > 0 && hits2.Load() > 0 {
		t.Fatalf("sticky cookie split traffic: hits1=%d hits2=%d", hits1.Load(), hits2.Load())
	}
	if hits1.Load()+hits2.Load() != 10 {
		t.Fatalf("hits = %d, want 10", hits1.Load()+hits2.Load())
	}
}

func TestStickySessionHeaderAffinity(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	seen := map[string]string{}
	handler := func(id string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			seen[r.Header.Get("X-Session-Id")] = id
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		})
	}
	srv1 := httptest.NewServer(handler("a"))
	defer srv1.Close()
	srv2 := httptest.NewServer(handler("b"))
	defer srv2.Close()

	p := newTestProxy(t, map[string]config.BackendRuntime{
		"b": {
			Name:     "b",
			Strategy: "round_robin",
			Instances: []config.InstanceRuntime{
				{URL: srv1.URL},
				{URL: srv2.URL},
			},
		},
	})
	route := &config.RouteRuntime{
		Name:        "r",
		BackendName: "b",
		Traffic: &config.RouteTrafficRuntime{
			Sticky: &config.RouteStickyRuntime{Header: "X-Session-Id"},
		},
	}

	for i := 0; i < 8; i++ {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.Header.Set("X-Session-Id", "sess-fixed")
		req.RemoteAddr = "203.0.113.10:1"
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req, route)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 {
		t.Fatalf("header sticky should pin one instance, saw %v", seen)
	}
}

func TestMirrorAsyncExcludesSensitiveData(t *testing.T) {
	t.Parallel()

	primaryHit := make(chan struct{}, 1)
	type mirrorCapture struct {
		Header http.Header
		Body   []byte
	}
	mirrorCh := make(chan mirrorCapture, 1)

	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		primaryHit <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	defer primary.Close()
	mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mirrorCh <- mirrorCapture{Header: r.Header.Clone(), Body: body}
		w.WriteHeader(http.StatusOK)
	}))
	defer mirror.Close()

	p := newTestProxy(t, map[string]config.BackendRuntime{
		"primary": {Name: "primary", Strategy: "round_robin", Instances: []config.InstanceRuntime{{URL: primary.URL}}},
		"shadow":  {Name: "shadow", Strategy: "round_robin", Instances: []config.InstanceRuntime{{URL: mirror.URL}}},
	})

	route := &config.RouteRuntime{
		Name:         "r",
		BackendName:  "primary",
		MaxBodyBytes: 1024,
		Traffic: &config.RouteTrafficRuntime{
			Mirror: &config.RouteMirrorRuntime{
				Backend:            "shadow",
				Percent:            100,
				MaxConcurrent:      4,
				Timeout:            time.Second,
				ExcludeRequestBody: true,
				ExcludeHeaders:     []string{"X-Api-Key"},
			},
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/orders", strings.NewReader(`{"secret":true}`))
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Cookie", "session=abc")
	req.Header.Set("X-Api-Key", "k")
	req.Header.Set("X-Trace", "keep-me")
	req.RemoteAddr = "203.0.113.10:1"
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req, route)

	select {
	case <-primaryHit:
	case <-time.After(2 * time.Second):
		t.Fatal("primary was not hit")
	}

	var mirrored mirrorCapture
	select {
	case mirrored = <-mirrorCh:
	case <-time.After(2 * time.Second):
		t.Fatal("mirror was not hit")
	}

	if mirrored.Header.Get("Authorization") != "" {
		t.Fatal("Authorization must not be mirrored")
	}
	if mirrored.Header.Get("Cookie") != "" {
		t.Fatal("Cookie must not be mirrored")
	}
	if mirrored.Header.Get("X-Api-Key") != "" {
		t.Fatal("exclude_headers must strip X-Api-Key")
	}
	if mirrored.Header.Get("X-Trace") != "keep-me" {
		t.Fatalf("X-Trace = %q, want keep-me", mirrored.Header.Get("X-Trace"))
	}
	if len(mirrored.Body) != 0 {
		t.Fatalf("mirror body = %q, want empty", mirrored.Body)
	}
}

func TestMirrorRespectsMaxConcurrentAndCancel(t *testing.T) {
	t.Parallel()

	started := make(chan struct{}, 8)
	release := make(chan struct{})
	var inFlight atomic.Int64
	var maxSeen atomic.Int64

	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer primary.Close()
	mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := inFlight.Add(1)
		for {
			old := maxSeen.Load()
			if n <= old || maxSeen.CompareAndSwap(old, n) {
				break
			}
		}
		started <- struct{}{}
		<-release
		inFlight.Add(-1)
		w.WriteHeader(http.StatusOK)
	}))
	defer mirror.Close()

	p := newTestProxy(t, map[string]config.BackendRuntime{
		"primary": {Name: "primary", Strategy: "round_robin", Instances: []config.InstanceRuntime{{URL: primary.URL}}},
		"shadow":  {Name: "shadow", Strategy: "round_robin", Instances: []config.InstanceRuntime{{URL: mirror.URL}}},
	})
	route := &config.RouteRuntime{
		Name:        "r",
		BackendName: "primary",
		Traffic: &config.RouteTrafficRuntime{
			Mirror: &config.RouteMirrorRuntime{
				Backend:       "shadow",
				Percent:       100,
				MaxConcurrent: 2,
				Timeout:       2 * time.Second,
			},
		},
	}

	for i := 0; i < 6; i++ {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.RemoteAddr = "203.0.113.10:1"
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req, route)
	}

	// Wait for the two admitted mirrors.
	deadline := time.After(2 * time.Second)
	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-deadline:
			t.Fatal("timed out waiting for mirror starts")
		}
	}

	if maxSeen.Load() > 2 {
		t.Fatalf("max in-flight mirrors = %d, want <= 2", maxSeen.Load())
	}

	close(release)
	p.Close() // must not hang: cancels mirror contexts and waits
}

func TestCanaryFallsBackWhenUnavailable(t *testing.T) {
	t.Parallel()

	stable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Backend", "stable")
		w.WriteHeader(http.StatusOK)
	}))
	defer stable.Close()

	p := newTestProxy(t, map[string]config.BackendRuntime{
		"stable": {Name: "stable", Strategy: "round_robin", Instances: []config.InstanceRuntime{{URL: stable.URL}}},
		"canary": {Name: "canary", Strategy: "round_robin", Instances: nil},
	})
	route := &config.RouteRuntime{
		Name:        "api",
		BackendName: "stable",
		Traffic: &config.RouteTrafficRuntime{
			Canary: &config.RouteCanaryRuntime{Backend: "canary", Percent: 100, KeyHeader: "X-User-Id"},
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Header.Set("X-User-Id", "u")
	req.RemoteAddr = "203.0.113.10:1"
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req, route)
	if got := rec.Header().Get("X-Backend"); got != "stable" {
		t.Fatalf("backend = %q, want stable fallback", got)
	}
}
