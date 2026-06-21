package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"algoryn.io/relay/internal/config"
)

// ── shouldRetry ───────────────────────────────────────────────────────────────

func TestShouldRetryNetworkError(t *testing.T) {
	t.Parallel()
	cfg := config.RetryConfig{Attempts: 3, On: []string{"network_error"}}
	if !shouldRetry(http.StatusBadGateway, true, cfg, http.MethodGet) {
		t.Error("expected retry on network_error for GET")
	}
}

func TestShouldRetry5xx(t *testing.T) {
	t.Parallel()
	cfg := config.RetryConfig{Attempts: 3, On: []string{"5xx"}}
	if !shouldRetry(http.StatusInternalServerError, false, cfg, http.MethodGet) {
		t.Error("expected retry on 5xx for GET")
	}
}

func TestShouldNotRetry4xx(t *testing.T) {
	t.Parallel()
	cfg := config.RetryConfig{Attempts: 3, On: []string{"5xx"}}
	if shouldRetry(http.StatusBadRequest, false, cfg, http.MethodGet) {
		t.Error("must not retry on 4xx")
	}
}

func TestShouldNotRetryUnsafeMethodByDefault(t *testing.T) {
	t.Parallel()
	cfg := config.RetryConfig{Attempts: 3, On: []string{"5xx"}}
	if shouldRetry(http.StatusInternalServerError, false, cfg, http.MethodPost) {
		t.Error("must not retry POST when AllowUnsafe is false")
	}
}

func TestShouldRetryUnsafeMethodWhenAllowed(t *testing.T) {
	t.Parallel()
	cfg := config.RetryConfig{Attempts: 3, On: []string{"5xx"}, AllowUnsafe: true}
	if !shouldRetry(http.StatusInternalServerError, false, cfg, http.MethodPost) {
		t.Error("expected retry on POST when AllowUnsafe is true")
	}
}

func TestShouldNotRetryWhenConditionsEmpty(t *testing.T) {
	t.Parallel()
	cfg := config.RetryConfig{Attempts: 3, On: []string{}}
	if shouldRetry(http.StatusInternalServerError, true, cfg, http.MethodGet) {
		t.Error("must not retry when On is empty")
	}
}

// ── computeBackoff ────────────────────────────────────────────────────────────

func TestComputeBackoffGrowsExponentially(t *testing.T) {
	t.Parallel()
	cfg := config.RetryConfig{BackoffInit: 100 * time.Millisecond, BackoffMax: 10 * time.Second}
	b0 := computeBackoff(0, cfg)
	b1 := computeBackoff(1, cfg)
	b2 := computeBackoff(2, cfg)

	if b1 <= b0 {
		t.Errorf("backoff should grow: attempt 1 (%v) <= attempt 0 (%v)", b1, b0)
	}
	if b2 <= b1 {
		t.Errorf("backoff should grow: attempt 2 (%v) <= attempt 1 (%v)", b2, b1)
	}
}

func TestComputeBackoffRespectsMax(t *testing.T) {
	t.Parallel()
	cfg := config.RetryConfig{BackoffInit: 100 * time.Millisecond, BackoffMax: 200 * time.Millisecond}
	// Attempt 5 would be 100ms * 2^5 = 3.2s without the cap.
	b := computeBackoff(5, cfg)
	if b > 220*time.Millisecond { // 10% jitter headroom above max
		t.Errorf("backoff %v exceeds max %v", b, cfg.BackoffMax)
	}
}

func TestComputeBackoffDefaultsWhenZero(t *testing.T) {
	t.Parallel()
	cfg := config.RetryConfig{} // zero → defaults
	b := computeBackoff(0, cfg)
	if b <= 0 {
		t.Errorf("backoff should be positive, got %v", b)
	}
}

// ── responseBuffer ────────────────────────────────────────────────────────────

func TestResponseBufferCapturesStatusAndBody(t *testing.T) {
	t.Parallel()
	buf := newResponseBuffer()
	buf.WriteHeader(http.StatusTeapot)
	_, _ = buf.Write([]byte("body"))

	if buf.Status() != http.StatusTeapot {
		t.Errorf("status = %d, want 418", buf.Status())
	}
	if buf.body.String() != "body" {
		t.Errorf("body = %q, want %q", buf.body.String(), "body")
	}
}

func TestResponseBufferDefaultStatus200(t *testing.T) {
	t.Parallel()
	buf := newResponseBuffer()
	_, _ = buf.Write([]byte("ok"))
	if buf.Status() != http.StatusOK {
		t.Errorf("status = %d, want 200", buf.Status())
	}
}

func TestResponseBufferFlushToWriter(t *testing.T) {
	t.Parallel()
	buf := newResponseBuffer()
	buf.header.Set("X-Custom", "relay")
	buf.WriteHeader(http.StatusAccepted)
	_, _ = buf.Write([]byte("content"))

	rr := httptest.NewRecorder()
	buf.flushTo(rr)

	if rr.Code != http.StatusAccepted {
		t.Errorf("flushed status = %d, want 202", rr.Code)
	}
	if rr.Header().Get("X-Custom") != "relay" {
		t.Errorf("X-Custom header missing after flush")
	}
	if rr.Body.String() != "content" {
		t.Errorf("flushed body = %q, want %q", rr.Body.String(), "content")
	}
}

// ── integration: retry loop ───────────────────────────────────────────────────

func TestProxyRetriesOn5xx(t *testing.T) {
	t.Parallel()

	calls := 0
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	rt := retryRuntime(backend.URL, config.RetryConfig{
		Attempts: 3,
		On:       []string{"5xx"},
	})
	proxy, err := New(rt, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer proxy.Close()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	proxy.ServeHTTP(rr, req, routeFor(rt))

	if calls != 3 {
		t.Errorf("expected 3 backend calls, got %d", calls)
	}
	if rr.Code != http.StatusOK {
		t.Errorf("final status = %d, want 200", rr.Code)
	}
}

func TestProxyExhaustsRetries(t *testing.T) {
	t.Parallel()

	calls := 0
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer backend.Close()

	rt := retryRuntime(backend.URL, config.RetryConfig{
		Attempts: 3,
		On:       []string{"5xx"},
	})
	proxy, err := New(rt, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer proxy.Close()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	proxy.ServeHTTP(rr, req, routeFor(rt))

	if calls != 3 {
		t.Errorf("expected 3 backend calls, got %d", calls)
	}
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("final status = %d, want 500", rr.Code)
	}
}

func TestProxyDoesNotRetryPostByDefault(t *testing.T) {
	t.Parallel()

	calls := 0
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer backend.Close()

	rt := retryRuntime(backend.URL, config.RetryConfig{
		Attempts: 3,
		On:       []string{"5xx"},
		// AllowUnsafe: false (default)
	})
	proxy, err := New(rt, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer proxy.Close()

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("body"))
	rr := httptest.NewRecorder()
	proxy.ServeHTTP(rr, req, routeFor(rt))

	if calls != 1 {
		t.Errorf("expected 1 backend call (no retry for POST), got %d", calls)
	}
}

func TestProxyNoRetryWhenAttemptsOne(t *testing.T) {
	t.Parallel()

	calls := 0
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer backend.Close()

	rt := retryRuntime(backend.URL, config.RetryConfig{
		Attempts: 1, // default: no retry
		On:       []string{"5xx"},
	})
	proxy, err := New(rt, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer proxy.Close()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()
	proxy.ServeHTTP(rr, req, routeFor(rt))

	if calls != 1 {
		t.Errorf("expected exactly 1 call, got %d", calls)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func retryRuntime(backendURL string, retryCfg config.RetryConfig) *config.RuntimeConfig {
	return &config.RuntimeConfig{
		Backends: map[string]config.BackendRuntime{
			"backend": {
				Name:      "backend",
				Strategy:  "round_robin",
				Retry:     retryCfg,
				Instances: []config.InstanceRuntime{{URL: backendURL}},
			},
		},
		Routes: map[string]config.RouteRuntime{
			"route": {
				Name:        "route",
				BackendName: "backend",
			},
		},
	}
}

func routeFor(rt *config.RuntimeConfig) *config.RouteRuntime {
	r := rt.Routes["route"]
	return &r
}
