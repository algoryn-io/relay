package middleware

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"algoryn.io/relay/internal/httpx"
)

func newExtAuthz(t *testing.T, server *httptest.Server, copyHeaders []string, failOpen bool) Middleware {
	t.Helper()
	mw, err := NewExtAuthz(ExtAuthzConfig{
		URL:         server.URL,
		CopyHeaders: copyHeaders,
		FailOpen:    failOpen,
		Client:      server.Client(),
	})
	if err != nil {
		t.Fatalf("NewExtAuthz() error = %v", err)
	}
	return mw
}

func TestExtAuthzAllowsOn2xx(t *testing.T) {
	t.Parallel()

	var gotMethod, gotURI string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Header.Get("X-Forwarded-Method")
		gotURI = r.Header.Get("X-Forwarded-Uri")
		w.Header().Set("X-User-Id", "alice")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	mw := newExtAuthz(t, server, []string{"X-User-Id"}, false)

	var injected string
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		injected = r.Header.Get("X-User-Id")
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/orders?x=1", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if injected != "alice" {
		t.Fatalf("copied header X-User-Id = %q, want alice", injected)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("forwarded method = %q, want POST", gotMethod)
	}
	if gotURI != "/orders?x=1" {
		t.Fatalf("forwarded uri = %q, want /orders?x=1", gotURI)
	}
}

func TestExtAuthzDeniesOn403(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(server.Close)

	var backendCalled atomic.Bool
	mw := newExtAuthz(t, server, nil, false)
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalled.Store(true)
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if backendCalled.Load() {
		t.Fatal("backend must not be called when authz denies")
	}
}

func TestExtAuthzDeniesOn401(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(server.Close)

	mw := newExtAuthz(t, server, nil, false)
	rec := httptest.NewRecorder()
	mw(okHandler()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestExtAuthzFailClosedWhenUnreachable(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	mw := newExtAuthz(t, server, nil, false)
	server.Close()

	rec := httptest.NewRecorder()
	mw(okHandler()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (fail closed)", rec.Code)
	}
}

func TestExtAuthzFailOpenWhenUnreachable(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	mw := newExtAuthz(t, server, nil, true)
	server.Close()

	var called atomic.Bool
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK || !called.Load() {
		t.Fatalf("fail_open should let request through: status=%d called=%v", rec.Code, called.Load())
	}
}

// Ensure the client IP resolved by the edge is forwarded to the authorizer.
func TestExtAuthzForwardsClientIP(t *testing.T) {
	t.Parallel()

	var gotXFF string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotXFF = r.Header.Get("X-Forwarded-For")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	mw := newExtAuthz(t, server, nil, false)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.9:1234"
	req = httpx.WithResolvedClientIP(req, nil)
	rec := httptest.NewRecorder()
	mw(okHandler()).ServeHTTP(rec, req)

	if gotXFF != "203.0.113.9" {
		t.Fatalf("forwarded X-Forwarded-For = %q, want 203.0.113.9", gotXFF)
	}
}
