package proxy

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"algoryn.io/relay/internal/config"
)

// ──────────────────────────────────────────────────────────────────────────────
// Unit tests for bulkhead primitive
// ──────────────────────────────────────────────────────────────────────────────

func TestBulkheadAcquireRelease(t *testing.T) {
	t.Parallel()

	bh := newBulkhead(2)
	if !bh.Acquire() {
		t.Fatal("first Acquire() = false, want true")
	}
	if !bh.Acquire() {
		t.Fatal("second Acquire() = false, want true")
	}
	bh.Release()
	bh.Release()
}

func TestBulkheadFullReturnsFalse(t *testing.T) {
	t.Parallel()

	bh := newBulkhead(1)
	if !bh.Acquire() {
		t.Fatal("first Acquire() = false")
	}
	if bh.Acquire() {
		t.Fatal("second Acquire() = true, want false (bulkhead full)")
	}
	bh.Release()
	// After release, a new acquire must succeed.
	if !bh.Acquire() {
		t.Fatal("Acquire() after Release() = false")
	}
	bh.Release()
}

func TestBulkheadInFlight(t *testing.T) {
	t.Parallel()

	bh := newBulkhead(3)
	if bh.InFlight() != 0 {
		t.Fatalf("InFlight() = %d, want 0", bh.InFlight())
	}
	_ = bh.Acquire()
	_ = bh.Acquire()
	if bh.InFlight() != 2 {
		t.Fatalf("InFlight() = %d, want 2", bh.InFlight())
	}
	bh.Release()
	if bh.InFlight() != 1 {
		t.Fatalf("InFlight() = %d, want 1 after Release", bh.InFlight())
	}
	bh.Release()
}

func TestBulkheadLimit(t *testing.T) {
	t.Parallel()

	bh := newBulkhead(5)
	if bh.Limit() != 5 {
		t.Fatalf("Limit() = %d, want 5", bh.Limit())
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Proxy-level integration tests
// ──────────────────────────────────────────────────────────────────────────────

func newBulkheadProxy(t *testing.T, backendURL string, maxConcurrent int) *Proxy {
	t.Helper()
	rt := &config.RuntimeConfig{
		Backends: map[string]config.BackendRuntime{
			"b": {
				Name:     "b",
				Strategy: "round_robin",
				Bulkhead: config.BulkheadConfig{MaxConcurrent: maxConcurrent},
				Instances: []config.InstanceRuntime{
					{URL: backendURL, Weight: 1},
				},
			},
		},
		Routes: map[string]config.RouteRuntime{
			"r": {Name: "r", BackendName: "b"},
		},
	}
	p, err := New(rt, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

// TestBulkheadProxyAllowsWhenUnderLimit verifies requests pass when concurrency
// is under the configured limit.
func TestBulkheadProxyAllowsWhenUnderLimit(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := newBulkheadProxy(t, srv.URL, 5)
	defer p.Close()

	route := p.backends["b"]
	rt := config.RouteRuntime{Name: "r", BackendName: "b", Backend: route}

	for i := 0; i < 5; i++ {
		rr := httptest.NewRecorder()
		p.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil), &rt)
		if rr.Code != http.StatusOK {
			t.Errorf("request %d: status = %d, want 200", i+1, rr.Code)
		}
	}
}

// TestBulkheadProxyRejects503WhenFull verifies that a request is rejected with
// 503 when the bulkhead is already at its concurrency limit.
func TestBulkheadProxyRejects503WhenFull(t *testing.T) {
	t.Parallel()

	// Backend blocks until unblocked.
	unblock := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-unblock
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := newBulkheadProxy(t, srv.URL, 1)
	defer p.Close()

	route := p.backends["b"]
	rt := config.RouteRuntime{Name: "r", BackendName: "b", Backend: route}

	// Start a request that will hold the single slot.
	ready := make(chan struct{})
	go func() {
		req := httptest.NewRequest(http.MethodGet, "/slow", nil)
		rr := httptest.NewRecorder()
		// Signal that we're about to call ServeHTTP.
		close(ready)
		p.ServeHTTP(rr, req, &rt)
	}()

	// Wait until the goroutine has started, then give it a moment to acquire
	// the bulkhead slot before we attempt the second request.
	<-ready
	time.Sleep(20 * time.Millisecond)

	// Second request must be rejected.
	rr2 := httptest.NewRecorder()
	p.ServeHTTP(rr2, httptest.NewRequest(http.MethodGet, "/fast", nil), &rt)
	if rr2.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rr2.Code)
	}

	// Unblock the backend so the goroutine can finish.
	close(unblock)
}

// TestBulkheadProxySlotReleasedAfterRequest verifies that the slot is freed
// after a request completes, allowing the next request through.
func TestBulkheadProxySlotReleasedAfterRequest(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := newBulkheadProxy(t, srv.URL, 1)
	defer p.Close()

	route := p.backends["b"]
	rt := config.RouteRuntime{Name: "r", BackendName: "b", Backend: route}

	for i := 0; i < 3; i++ {
		rr := httptest.NewRecorder()
		p.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil), &rt)
		if rr.Code != http.StatusOK {
			t.Errorf("sequential request %d: status = %d, want 200", i+1, rr.Code)
		}
	}
}

// TestBulkheadDisabledByDefault verifies that without a bulkhead config,
// any number of concurrent requests are allowed.
func TestBulkheadDisabledByDefault(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rt := &config.RuntimeConfig{
		Backends: map[string]config.BackendRuntime{
			"b": {
				Name:      "b",
				Strategy:  "round_robin",
				Instances: []config.InstanceRuntime{{URL: srv.URL, Weight: 1}},
				// No Bulkhead config
			},
		},
		Routes: map[string]config.RouteRuntime{
			"r": {Name: "r", BackendName: "b"},
		},
	}
	p, err := New(rt, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer p.Close()

	if _, hasBH := p.bulkheads["b"]; hasBH {
		t.Error("bulkhead registered when max_concurrent = 0, want none")
	}

	route := config.RouteRuntime{Name: "r", BackendName: "b", Backend: rt.Backends["b"]}
	for i := 0; i < 10; i++ {
		rr := httptest.NewRecorder()
		p.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil), &route)
		if rr.Code != http.StatusOK {
			t.Errorf("request %d: status = %d, want 200", i+1, rr.Code)
		}
	}
}

// TestBulkheadConcurrencyNeverExceedsLimit verifies that under concurrent load
// the number of in-flight requests never exceeds the configured maximum.
func TestBulkheadConcurrencyNeverExceedsLimit(t *testing.T) {
	t.Parallel()

	const maxConcurrent = 3
	var peak atomic.Int64
	var current atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := current.Add(1)
		if n > peak.Load() {
			peak.Store(n)
		}
		time.Sleep(5 * time.Millisecond)
		current.Add(-1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := newBulkheadProxy(t, srv.URL, maxConcurrent)
	defer p.Close()

	route := p.backends["b"]
	rt := config.RouteRuntime{Name: "r", BackendName: "b", Backend: route}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rr := httptest.NewRecorder()
			p.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil), &rt)
		}()
	}
	wg.Wait()

	if peak.Load() > maxConcurrent {
		t.Errorf("peak concurrency = %d, must not exceed limit %d", peak.Load(), maxConcurrent)
	}
}

// TestBulkheadValidationRejectsNegative verifies that a negative max_concurrent
// fails config validation.
func TestBulkheadValidationRejectsNegative(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		Listener: config.ListenerConfig{
			HTTP:     config.HTTPConfig{Port: 8080},
			Timeouts: config.TimeoutsConfig{Read: time.Second, Write: time.Second, Idle: time.Second},
		},
		Observability: config.ObservabilityConfig{
			Metrics: config.MetricsConfig{FlushInterval: time.Second},
		},
		Backends: []config.BackendConfig{
			{
				Name:     "b",
				Strategy: "round_robin",
				Bulkhead: config.BulkheadConfig{MaxConcurrent: -1},
				Instances: []config.InstanceConfig{
					{URL: "http://127.0.0.1:9000"},
				},
			},
		},
		Routes: []config.RouteConfig{
			{Name: "r", Backend: "b", Match: config.MatchConfig{
				Path:    "/",
				Methods: []string{"GET"},
			}},
		},
	}

	_, err := config.BuildRuntime(cfg)
	if err == nil {
		t.Error("expected validation error for max_concurrent = -1, got nil")
	}
}
