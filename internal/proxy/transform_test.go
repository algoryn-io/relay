package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"algoryn.io/relay/internal/config"
)

// proxyWithBackend builds a Proxy wired to a single-instance backend and
// returns the proxy, a base RouteRuntime pointing at that backend, and a
// cleanup function that stops the backend and closes the proxy.
func proxyWithBackend(handler http.HandlerFunc) (*Proxy, *config.RouteRuntime, func()) {
	srv := httptest.NewServer(handler)
	rt := &config.RuntimeConfig{
		Backends: map[string]config.BackendRuntime{
			"svc": {
				Name:      "svc",
				Strategy:  "round_robin",
				Instances: []config.InstanceRuntime{{URL: srv.URL, Weight: 1}},
			},
		},
	}
	p, _ := New(rt, nil)
	route := &config.RouteRuntime{
		Name:        "test",
		BackendName: "svc",
		Backend:     rt.Backends["svc"],
	}
	return p, route, func() {
		p.Close()
		srv.Close()
	}
}

// ── path rewriting ────────────────────────────────────────────────────────────

func TestPathRewriteNumberedGroup(t *testing.T) {
	t.Parallel()

	p, route, cleanup := proxyWithBackend(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Got-Path", r.URL.Path)
		_, _ = w.Write([]byte("ok"))
	})
	defer cleanup()

	re, err := buildRewriteFromConfig(`^/api/v1/users/([^/]+)$`, `/users/$1`)
	if err != nil {
		t.Fatalf("build rewrite: %v", err)
	}
	route.Rewrite = re

	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/users/alice", nil), route)

	if got := rec.Header().Get("X-Got-Path"); got != "/users/alice" {
		t.Errorf("path = %q, want /users/alice", got)
	}
}

func TestPathRewriteNamedGroup(t *testing.T) {
	t.Parallel()

	p, route, cleanup := proxyWithBackend(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Got-Path", r.URL.Path)
		_, _ = w.Write([]byte("ok"))
	})
	defer cleanup()

	re, err := buildRewriteFromConfig(`^/api/v2/items/(?P<id>[^/]+)$`, `/v2/catalog/${id}`)
	if err != nil {
		t.Fatalf("build rewrite: %v", err)
	}
	route.Rewrite = re

	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v2/items/42", nil), route)

	if got := rec.Header().Get("X-Got-Path"); got != "/v2/catalog/42" {
		t.Errorf("path = %q, want /v2/catalog/42", got)
	}
}

func TestPathRewriteNoMatchLeavesPathUnchanged(t *testing.T) {
	t.Parallel()

	p, route, cleanup := proxyWithBackend(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Got-Path", r.URL.Path)
		_, _ = w.Write([]byte("ok"))
	})
	defer cleanup()

	re, err := buildRewriteFromConfig(`^/only-this$`, `/replaced`)
	if err != nil {
		t.Fatalf("build rewrite: %v", err)
	}
	route.Rewrite = re

	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/something-else", nil), route)

	if got := rec.Header().Get("X-Got-Path"); got != "/something-else" {
		t.Errorf("path = %q, want /something-else (no match)", got)
	}
}

func TestPathRewriteNilRuleSkipped(t *testing.T) {
	t.Parallel()

	p, route, cleanup := proxyWithBackend(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Got-Path", r.URL.Path)
		_, _ = w.Write([]byte("ok"))
	})
	defer cleanup()
	route.Rewrite = nil

	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/unchanged", nil), route)

	if got := rec.Header().Get("X-Got-Path"); got != "/api/unchanged" {
		t.Errorf("path = %q, want /api/unchanged", got)
	}
}

// ── body size limit ─────────���────────────────────────────��────────────────────

func TestBodyLimitRejects413WhenExceeded(t *testing.T) {
	t.Parallel()

	p, route, cleanup := proxyWithBackend(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("should not reach backend"))
	})
	defer cleanup()
	route.MaxBodyBytes = 10

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(strings.Repeat("x", 20)))
	p.ServeHTTP(rec, req, route)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", rec.Code)
	}
}

func TestBodyLimitAllowsBodyWithinLimit(t *testing.T) {
	t.Parallel()

	var receivedBody []byte
	p, route, cleanup := proxyWithBackend(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte("ok"))
	})
	defer cleanup()
	route.MaxBodyBytes = 100

	payload := []byte("hello world")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/upload", bytes.NewReader(payload))
	p.ServeHTTP(rec, req, route)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !bytes.Equal(receivedBody, payload) {
		t.Errorf("body = %q, want %q", receivedBody, payload)
	}
}

func TestBodyLimitZeroMeansNoLimit(t *testing.T) {
	t.Parallel()

	var receivedLen int
	p, route, cleanup := proxyWithBackend(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		receivedLen = len(data)
		_, _ = w.Write([]byte("ok"))
	})
	defer cleanup()
	route.MaxBodyBytes = 0 // disabled

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/big", strings.NewReader(strings.Repeat("z", 500)))
	p.ServeHTTP(rec, req, route)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if receivedLen != 500 {
		t.Errorf("received %d bytes, want 500", receivedLen)
	}
}

func TestBodyLimitWithRetryReplaysBody(t *testing.T) {
	t.Parallel()

	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		data, _ := io.ReadAll(r.Body)
		_, _ = w.Write(data)
	}))
	defer srv.Close()

	retryBackend := config.BackendRuntime{
		Name:     "svc",
		Strategy: "round_robin",
		Retry: config.RetryConfig{
			Attempts:    3,
			BackoffInit: time.Millisecond,
			On:          []string{"5xx"},
			AllowUnsafe: true, // POST requires this for retry
		},
		Instances: []config.InstanceRuntime{{URL: srv.URL, Weight: 1}},
	}
	p, _ := New(&config.RuntimeConfig{
		Backends: map[string]config.BackendRuntime{"svc": retryBackend},
	}, nil)
	defer p.Close()

	route := &config.RouteRuntime{
		Name:         "test",
		BackendName:  "svc",
		MaxBodyBytes: 1024,
		Backend:      retryBackend,
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("retry-me"))
	p.ServeHTTP(rec, req, route)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if body := rec.Body.String(); body != "retry-me" {
		t.Errorf("body = %q, want retry-me", body)
	}
}

// ── header injection ──────────────���───────────────────────────────────────────

func TestAddRequestHeadersStaticValue(t *testing.T) {
	t.Parallel()

	var got string
	p, route, cleanup := proxyWithBackend(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Service")
		_, _ = w.Write([]byte("ok"))
	})
	defer cleanup()
	route.AddRequestHeaders = map[string]string{"X-Service": "relay"}

	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil), route)

	if got != "relay" {
		t.Errorf("X-Service = %q, want relay", got)
	}
}

func TestAddRequestHeadersCopiesIncomingHeader(t *testing.T) {
	t.Parallel()

	var gotUserID string
	p, route, cleanup := proxyWithBackend(func(w http.ResponseWriter, r *http.Request) {
		gotUserID = r.Header.Get("X-User-ID")
		_, _ = w.Write([]byte("ok"))
	})
	defer cleanup()
	// Simulate: JWT middleware already set X-Authenticated-Sub; route renames it.
	route.AddRequestHeaders = map[string]string{
		"X-User-ID": "${req.X-Authenticated-Sub}",
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Authenticated-Sub", "user-42")
	p.ServeHTTP(httptest.NewRecorder(), req, route)

	if gotUserID != "user-42" {
		t.Errorf("X-User-ID = %q, want user-42", gotUserID)
	}
}

func TestAddRequestHeadersMissingSourceIsEmpty(t *testing.T) {
	t.Parallel()

	var gotTenant string
	p, route, cleanup := proxyWithBackend(func(w http.ResponseWriter, r *http.Request) {
		gotTenant = r.Header.Get("X-Tenant")
		_, _ = w.Write([]byte("ok"))
	})
	defer cleanup()
	route.AddRequestHeaders = map[string]string{"X-Tenant": "${req.X-Missing}"}

	p.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil), route)

	if gotTenant != "" {
		t.Errorf("X-Tenant = %q, want empty string", gotTenant)
	}
}

// ── resolveHeaderTpl unit tests ──────────���────────────────────────────────────

func TestResolveHeaderTplStaticValue(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if got := resolveHeaderTpl("static-value", req); got != "static-value" {
		t.Errorf("= %q, want static-value", got)
	}
}

func TestResolveHeaderTplCopiesHeader(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Sub", "user123")
	if got := resolveHeaderTpl("${req.X-Sub}", req); got != "user123" {
		t.Errorf("= %q, want user123", got)
	}
}

func TestResolveHeaderTplMissingHeaderIsEmpty(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if got := resolveHeaderTpl("${req.X-Not-Present}", req); got != "" {
		t.Errorf("= %q, want empty", got)
	}
}

func TestResolveHeaderTplMalformedTemplateIsLiteral(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	tpl := "${req.X-Sub" // missing closing brace
	if got := resolveHeaderTpl(tpl, req); got != tpl {
		t.Errorf("= %q, want literal %q", got, tpl)
	}
}

// ── helpers ─────────────────────────────────���─────────────────────────────────

// buildRewriteFromConfig compiles a RewriteRule into a CompiledRewrite.
// It exercises the same regexp.Compile path used by BuildRuntime at startup.
func buildRewriteFromConfig(pattern, replacement string) (*config.CompiledRewrite, error) {
	return config.NewCompiledRewrite(pattern, replacement)
}
