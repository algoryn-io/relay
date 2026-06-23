package proxy

import (
	"net/http"
	"sync"
	"time"
)

type cbState int8

const (
	cbClosed   cbState = iota // normal operation
	cbOpen                    // tripped; requests rejected
	cbHalfOpen                // probing after timeout
)

func (s cbState) String() string {
	switch s {
	case cbClosed:
		return "closed"
	case cbOpen:
		return "open"
	case cbHalfOpen:
		return "half_open"
	default:
		return "unknown"
	}
}

// CircuitBreaker is a per-instance, consecutive-failure circuit breaker.
//
// Transitions:
//
//	Closed   --(consecutive failures >= threshold)--> Open
//	Open     --(timeout elapsed, one probe admitted)--> HalfOpen
//	HalfOpen --(probe success)----------------------> Closed
//	HalfOpen --(probe failure)----------------------> Open (timer reset)
//
// In HalfOpen exactly one probe request is admitted; all others are rejected
// until the probe resolves, so a recovering backend is not flooded. The failure
// counter only counts *consecutive* failures — any success resets it to zero, so
// an old burst of errors cannot re-trip the circuit on its own.
type CircuitBreaker struct {
	mu        sync.Mutex
	state     cbState
	failures  int
	threshold int
	timeout   time.Duration
	trippedAt time.Time
	probing   bool // true while a half-open probe is in flight
}

func newCircuitBreaker(threshold int, timeout time.Duration) *CircuitBreaker {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &CircuitBreaker{
		threshold: threshold,
		timeout:   timeout,
	}
}

// IsOpen returns true when the circuit is fully Open (not HalfOpen).
// Read-only — does not transition state; safe to call during instance selection.
func (cb *CircuitBreaker) IsOpen() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.state == cbOpen && time.Since(cb.trippedAt) < cb.timeout
}

// Allow reports whether the request should proceed, transitioning Open→HalfOpen
// once the timeout elapses. In HalfOpen it admits exactly one probe: the first
// caller proceeds and subsequent callers are rejected until the probe resolves.
func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	switch cb.state {
	case cbClosed:
		return true
	case cbOpen:
		if time.Since(cb.trippedAt) < cb.timeout {
			return false
		}
		// Timeout elapsed: enter half-open and admit this caller as the probe.
		cb.state = cbHalfOpen
		cb.probing = true
		return true
	case cbHalfOpen:
		if cb.probing {
			return false // a probe is already in flight
		}
		cb.probing = true
		return true
	default:
		return true
	}
}

// RecordSuccess closes the circuit and resets the failure counter.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures = 0
	cb.probing = false
	cb.state = cbClosed
}

// RecordFailure records a failed outcome. A probe failure in HalfOpen reopens
// the circuit immediately; in Closed it counts consecutive failures and trips
// when the threshold is reached. Failures recorded while already Open are
// ignored (they belong to requests that started before the trip).
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	switch cb.state {
	case cbHalfOpen:
		cb.state = cbOpen
		cb.trippedAt = time.Now()
		cb.probing = false
		cb.failures = 0
	case cbClosed:
		cb.failures++
		if cb.failures >= cb.threshold {
			cb.state = cbOpen
			cb.trippedAt = time.Now()
			cb.failures = 0
		}
	case cbOpen:
		// Already open; ignore late failures from in-flight requests.
	}
}

// State returns a human-readable label, accounting for elapsed timeout.
func (cb *CircuitBreaker) State() string {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if cb.state == cbOpen && time.Since(cb.trippedAt) >= cb.timeout {
		return cbHalfOpen.String()
	}
	return cb.state.String()
}

// circuitTransport wraps an http.RoundTripper and records outcomes on the circuit.
// Transport errors and 5xx responses increment the failure counter;
// everything else is recorded as a success.
type circuitTransport struct {
	base    http.RoundTripper
	circuit *CircuitBreaker
}

func (t *circuitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil || (resp != nil && resp.StatusCode >= 500) {
		t.circuit.RecordFailure()
	} else {
		t.circuit.RecordSuccess()
	}
	return resp, err
}
