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
//	Closed   --(failures >= threshold)--> Open
//	Open     --(timeout elapsed)-------> HalfOpen
//	HalfOpen --(next success)----------> Closed
//	HalfOpen --(next failure)----------> Open (timer reset)
type CircuitBreaker struct {
	mu        sync.Mutex
	state     cbState
	failures  int
	threshold int
	timeout   time.Duration
	trippedAt time.Time
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

// Allow transitions Open→HalfOpen once the timeout elapses and returns
// whether the request should proceed. Returns false only while fully Open.
func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if cb.state == cbOpen {
		if time.Since(cb.trippedAt) < cb.timeout {
			return false
		}
		cb.state = cbHalfOpen
	}
	return true
}

// RecordSuccess closes the circuit and resets the failure counter.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures = 0
	cb.state = cbClosed
}

// RecordFailure increments the failure counter. Trips the circuit when
// failures >= threshold, or immediately if already in HalfOpen.
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures++
	if cb.state == cbHalfOpen || cb.failures >= cb.threshold {
		cb.state = cbOpen
		cb.trippedAt = time.Now()
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
