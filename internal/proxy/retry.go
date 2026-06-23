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

// maxRetryResponseBuffer caps how many response bytes are held in memory while
// a request is retry-eligible. Once a response exceeds this size the buffer
// "commits": the bytes seen so far are written to the real ResponseWriter and
// the remainder streams through directly. The request can no longer be retried
// (bytes are already on the wire), which is correct — retries only matter before
// any response is committed to the client. This bounds per-request memory so a
// large upstream response can never OOM the gateway.
const maxRetryResponseBuffer = 1 << 20 // 1 MB

// responseBuffer captures an HTTP response so the retry loop can inspect the
// status code before committing bytes to the real ResponseWriter. It buffers up
// to maxRetryResponseBuffer bytes; beyond that it commits and streams through to
// target, so memory stays bounded regardless of upstream response size.
//
// It is used only on retry-eligible requests. Non-retryable requests stream
// straight to the real ResponseWriter without any buffering (see Proxy.ServeHTTP).
type responseBuffer struct {
	target    http.ResponseWriter // real writer; passthrough destination after commit
	header    http.Header
	status    int
	body      bytes.Buffer
	cap       int  // max bytes to buffer before committing to target
	committed bool // true once headers+bytes have been written to target
}

func newResponseBuffer(target http.ResponseWriter, cap int) *responseBuffer {
	return &responseBuffer{target: target, header: make(http.Header), cap: cap}
}

func (b *responseBuffer) Header() http.Header {
	if b.committed {
		return b.target.Header()
	}
	return b.header
}

func (b *responseBuffer) WriteHeader(code int) {
	if b.status == 0 {
		b.status = code
	}
}

func (b *responseBuffer) Write(p []byte) (int, error) {
	if b.status == 0 {
		b.status = http.StatusOK
	}
	if b.committed {
		return b.target.Write(p)
	}
	if b.cap > 0 && b.body.Len()+len(p) > b.cap {
		// Exceeding the cap: flush what we have and switch to passthrough.
		b.commit()
		return b.target.Write(p)
	}
	return b.body.Write(p)
}

// Flush forwards to the real writer only once committed; while buffering it is a
// no-op (the response is held for retry inspection).
func (b *responseBuffer) Flush() {
	if b.committed {
		if f, ok := b.target.(http.Flusher); ok {
			f.Flush()
		}
	}
}

func (b *responseBuffer) Status() int {
	if b.status == 0 {
		return http.StatusOK
	}
	return b.status
}

// commit writes the buffered headers and body to the real ResponseWriter and
// marks the buffer as committed; subsequent writes pass straight through.
func (b *responseBuffer) commit() {
	if b.committed {
		return
	}
	dst := b.target.Header()
	for k, vs := range b.header {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
	b.target.WriteHeader(b.Status())
	if b.body.Len() > 0 {
		_, _ = b.target.Write(b.body.Bytes())
		b.body.Reset()
	}
	b.committed = true
}

// flushTo writes the buffered response to the real ResponseWriter. It is a no-op
// when the buffer already committed (the response is on the wire).
func (b *responseBuffer) flushTo(w http.ResponseWriter) {
	if b.committed {
		return
	}
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
