package proxy

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"algoryn.io/relay/internal/config"
)

// ── unit tests for CircuitBreaker ────────────────────────────────────────────

func TestCircuitBreakerStartsClosed(t *testing.T) {
	t.Parallel()
	cb := newCircuitBreaker(3, time.Second)
	if cb.State() != "closed" {
		t.Fatalf("state = %q, want closed", cb.State())
	}
	if !cb.Allow() {
		t.Fatal("Allow() = false, want true for closed circuit")
	}
}

func TestCircuitBreakerTripsAfterThreshold(t *testing.T) {
	t.Parallel()
	cb := newCircuitBreaker(3, time.Hour)

	cb.RecordFailure()
	cb.RecordFailure()
	if cb.State() != "closed" {
		t.Fatalf("state = %q after 2 failures, want closed", cb.State())
	}
	cb.RecordFailure()
	if cb.State() != "open" {
		t.Fatalf("state = %q after threshold, want open", cb.State())
	}
	if cb.Allow() {
		t.Fatal("Allow() = true, want false for open circuit")
	}
}

func TestCircuitBreakerSuccessResetsFailures(t *testing.T) {
	t.Parallel()
	cb := newCircuitBreaker(3, time.Hour)

	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordSuccess()
	cb.RecordFailure()
	cb.RecordFailure()

	if cb.State() != "closed" {
		t.Fatalf("state = %q after reset, want closed", cb.State())
	}
}

func TestCircuitBreakerTransitionsToHalfOpenAfterTimeout(t *testing.T) {
	t.Parallel()
	cb := newCircuitBreaker(1, 10*time.Millisecond)
	cb.RecordFailure()

	if cb.Allow() {
		t.Fatal("Allow() = true before timeout, want false")
	}

	time.Sleep(20 * time.Millisecond)

	if !cb.Allow() {
		t.Fatal("Allow() = false after timeout, want true (half-open)")
	}
	if cb.State() != "half_open" {
		t.Fatalf("state = %q after timeout, want half_open", cb.State())
	}
}

func TestCircuitBreakerHalfOpenSuccessCloses(t *testing.T) {
	t.Parallel()
	cb := newCircuitBreaker(1, 10*time.Millisecond)
	cb.RecordFailure()
	time.Sleep(20 * time.Millisecond)

	cb.Allow() // transition to half_open
	cb.RecordSuccess()

	if cb.State() != "closed" {
		t.Fatalf("state = %q after half-open success, want closed", cb.State())
	}
}

func TestCircuitBreakerHalfOpenFailureReopens(t *testing.T) {
	t.Parallel()
	cb := newCircuitBreaker(1, 10*time.Millisecond)
	cb.RecordFailure()
	time.Sleep(20 * time.Millisecond)

	cb.Allow() // transition to half_open
	cb.RecordFailure()

	if cb.State() != "open" {
		t.Fatalf("state = %q after half-open failure, want open", cb.State())
	}
}

func TestCircuitBreakerHalfOpenAdmitsSingleProbe(t *testing.T) {
	t.Parallel()
	cb := newCircuitBreaker(1, 10*time.Millisecond)
	cb.RecordFailure()
	time.Sleep(20 * time.Millisecond)

	// First Allow after timeout admits the probe.
	if !cb.Allow() {
		t.Fatal("first Allow() after timeout = false, want true (probe)")
	}
	// While the probe is in flight, all other callers are rejected.
	if cb.Allow() {
		t.Fatal("second concurrent Allow() = true, want false (single probe)")
	}
	if cb.Allow() {
		t.Fatal("third concurrent Allow() = true, want false (single probe)")
	}

	// Probe fails → reopen; within the new timeout window Allow stays false.
	cb.RecordFailure()
	if cb.Allow() {
		t.Fatal("Allow() = true right after probe failure, want false (reopened)")
	}
}

func TestCircuitBreakerOldBurstDoesNotRetripAfterSuccess(t *testing.T) {
	t.Parallel()
	cb := newCircuitBreaker(3, time.Hour)

	// Two failures (below threshold), then a success resets the counter.
	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordSuccess()

	// A single later failure must not trip — the old burst decayed.
	cb.RecordFailure()
	if cb.State() != "closed" {
		t.Fatalf("state = %q, want closed (old burst should not count)", cb.State())
	}
}

func TestCircuitBreakerIsOpenReadOnly(t *testing.T) {
	t.Parallel()
	cb := newCircuitBreaker(1, 10*time.Millisecond)
	cb.RecordFailure()

	if !cb.IsOpen() {
		t.Fatal("IsOpen() = false immediately after trip, want true")
	}

	time.Sleep(20 * time.Millisecond)

	// Timeout elapsed → would be half_open; IsOpen() should return false.
	if cb.IsOpen() {
		t.Fatal("IsOpen() = true after timeout, want false")
	}
	// State() reflects the half_open assessment.
	if cb.State() != "half_open" {
		t.Fatalf("State() = %q after timeout, want half_open", cb.State())
	}
	// IsOpen() must not have transitioned state; Allow() does it.
	if cb.state != cbOpen {
		t.Fatal("IsOpen() must not transition internal state")
	}
}

// ── integration tests via proxy ───────────────────────────────────────────────

func TestProxyCircuitBreakerTripsAndRejects(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(backend.Close)

	p := newTestProxy(t, cbBackends(backend.URL, 3, 100*time.Millisecond))
	route := &config.RouteRuntime{BackendName: "svc"}

	// 3 requests to trip the circuit (threshold=3, all get 500 → RecordFailure)
	for range 3 {
		performProxyRequest(t, p, route, "GET", "/").Body.Close()
	}

	// 4th request must be rejected by the open circuit (503)
	resp := performProxyRequest(t, p, route, "GET", "/")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (circuit open)", resp.StatusCode)
	}
	// Backend must not have received the 4th call.
	if calls.Load() != 3 {
		t.Fatalf("backend calls = %d, want 3 (circuit should have blocked 4th)", calls.Load())
	}
}

func TestProxyCircuitBreakerHalfOpenRecovery(t *testing.T) {
	t.Parallel()

	var healthy atomic.Bool
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if healthy.Load() {
			w.WriteHeader(http.StatusOK)
		} else {
			http.Error(w, "down", http.StatusInternalServerError)
		}
	}))
	t.Cleanup(backend.Close)

	p := newTestProxy(t, cbBackends(backend.URL, 2, 20*time.Millisecond))
	route := &config.RouteRuntime{BackendName: "svc"}

	// Trip the circuit
	performProxyRequest(t, p, route, "GET", "/").Body.Close()
	performProxyRequest(t, p, route, "GET", "/").Body.Close()

	// Wait for half-open window
	time.Sleep(30 * time.Millisecond)

	// Recovery: mark backend healthy and probe
	healthy.Store(true)
	resp := performProxyRequest(t, p, route, "GET", "/")
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("probe status = %d, want 200", resp.StatusCode)
	}

	// Circuit must be closed; subsequent request goes through normally
	resp2 := performProxyRequest(t, p, route, "GET", "/")
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("post-recovery status = %d, want 200", resp2.StatusCode)
	}
}

func TestProxyCircuitBreakerFallsBackToHealthyInstance(t *testing.T) {
	t.Parallel()

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	t.Cleanup(bad.Close)

	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(good.Close)

	p := newTestProxy(t, map[string]config.BackendRuntime{
		"svc": {
			Name:     "svc",
			Strategy: "round_robin",
			CircuitBreaker: config.CircuitBreakerConfig{
				Threshold: 2,
				Timeout:   time.Hour,
			},
			Instances: []config.InstanceRuntime{
				{URL: bad.URL},
				{URL: good.URL},
			},
		},
	})
	route := &config.RouteRuntime{BackendName: "svc"}

	// Trip the circuit on the bad instance (round-robin starts at bad)
	performProxyRequest(t, p, route, "GET", "/").Body.Close() // bad (RR idx 0)
	performProxyRequest(t, p, route, "GET", "/").Body.Close() // good (RR idx 1) - success
	performProxyRequest(t, p, route, "GET", "/").Body.Close() // bad again → 2nd failure → trip

	// Now bad is open; all requests must go to good
	for range 4 {
		resp := performProxyRequest(t, p, route, "GET", "/")
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected fallback to good instance (200), got %d", resp.StatusCode)
		}
	}
}

// cbBackends returns a single-instance backend map with circuit breaker enabled.
func cbBackends(url string, threshold int, timeout time.Duration) map[string]config.BackendRuntime {
	return map[string]config.BackendRuntime{
		"svc": {
			Name:     "svc",
			Strategy: "round_robin",
			CircuitBreaker: config.CircuitBreakerConfig{
				Threshold: threshold,
				Timeout:   timeout,
			},
			Instances: []config.InstanceRuntime{{URL: url}},
		},
	}
}
