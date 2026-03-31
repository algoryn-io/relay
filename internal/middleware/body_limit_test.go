package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBodyLimitUnderLimitPasses(t *testing.T) {
	t.Parallel()

	mw := mustBodyLimit(t, BodyLimitConfig{MaxBytes: 5})
	called := false
	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("ReadAll() error = %v", err)
		}
		if string(body) != "test" {
			t.Fatalf("body = %q, want test", string(body))
		}
		w.WriteHeader(http.StatusOK)
	}), mw)

	req := httptest.NewRequest(http.MethodPost, "/upload", bytes.NewBufferString("test"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !called {
		t.Fatal("expected downstream handler to be called")
	}
}

func TestBodyLimitOverLimitReturns413(t *testing.T) {
	t.Parallel()

	mw := mustBodyLimit(t, BodyLimitConfig{MaxBytes: 4})
	called := false
	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}), mw)

	req := httptest.NewRequest(http.MethodPost, "/upload", bytes.NewBufferString("12345"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
	}
	if called {
		t.Fatal("downstream handler should not be called when body exceeds limit")
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if body["error"] != "request_too_large" {
		t.Fatalf("error = %q, want request_too_large", body["error"])
	}
	if body["status"] != "error" {
		t.Fatalf("status = %q, want error", body["status"])
	}
}

func TestBodyLimitExactLimitPasses(t *testing.T) {
	t.Parallel()

	mw := mustBodyLimit(t, BodyLimitConfig{MaxBytes: 4})
	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			t.Fatalf("ReadAll() error = %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}), mw)

	req := httptest.NewRequest(http.MethodPost, "/upload", bytes.NewBufferString("1234"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestBodyLimitDownstreamNotCalledWhenExceeded(t *testing.T) {
	t.Parallel()

	mw := mustBodyLimit(t, BodyLimitConfig{MaxBytes: 1})
	calls := 0
	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}), mw)

	req := httptest.NewRequest(http.MethodPost, "/upload", bytes.NewBufferString("ab"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if calls != 0 {
		t.Fatalf("downstream calls = %d, want 0", calls)
	}
}

func mustBodyLimit(t *testing.T, cfg BodyLimitConfig) Middleware {
	t.Helper()
	mw, err := NewBodyLimit(cfg)
	if err != nil {
		t.Fatalf("NewBodyLimit() error = %v", err)
	}
	return mw
}
