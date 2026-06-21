package proxy

import (
	"bytes"
	"math"
	"math/rand/v2"
	"net/http"
	"strings"
	"time"

	"algoryn.io/relay/internal/config"
)

// responseBuffer captures an HTTP response so the retry loop can inspect the
// status code before committing bytes to the real ResponseWriter.
type responseBuffer struct {
	header     http.Header
	status     int
	body       bytes.Buffer
	networkErr error // set by ErrorHandler when the transport fails
}

func newResponseBuffer() *responseBuffer {
	return &responseBuffer{header: make(http.Header)}
}

func (b *responseBuffer) Header() http.Header { return b.header }

func (b *responseBuffer) WriteHeader(code int) {
	if b.status == 0 {
		b.status = code
	}
}

func (b *responseBuffer) Write(p []byte) (int, error) {
	if b.status == 0 {
		b.status = http.StatusOK
	}
	return b.body.Write(p)
}

// Flush is a no-op: we buffer the full response for retry inspection.
func (b *responseBuffer) Flush() {}

func (b *responseBuffer) Status() int {
	if b.status == 0 {
		return http.StatusOK
	}
	return b.status
}

// flushTo writes the buffered response to the real ResponseWriter.
func (b *responseBuffer) flushTo(w http.ResponseWriter) {
	for k, vs := range b.header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(b.Status())
	_, _ = w.Write(b.body.Bytes())
}

// shouldRetry returns true when the response warrants another attempt.
func shouldRetry(status int, isNetErr bool, cfg config.RetryConfig, method string) bool {
	if !cfg.AllowUnsafe && !isSafeMethod(method) {
		return false
	}
	for _, cond := range cfg.On {
		switch strings.ToLower(cond) {
		case "5xx":
			if status >= 500 {
				return true
			}
		case "network_error":
			if isNetErr {
				return true
			}
		}
	}
	return false
}

func isSafeMethod(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	}
	return false
}

// computeBackoff returns the wait duration for the given attempt index (0-based).
// Uses exponential backoff with ±10% jitter.
func computeBackoff(attempt int, cfg config.RetryConfig) time.Duration {
	init := cfg.BackoffInit
	if init <= 0 {
		init = 100 * time.Millisecond
	}
	max := cfg.BackoffMax
	if max <= 0 {
		max = time.Second
	}

	exp := float64(init) * math.Pow(2, float64(attempt))
	// ±10% jitter
	jitter := exp * 0.1 * (2*rand.Float64() - 1)
	d := time.Duration(exp + jitter)
	if d > max {
		d = max
	}
	return d
}
