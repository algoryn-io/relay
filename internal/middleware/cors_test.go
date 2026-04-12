package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCORSAllowedOriginOnNormalRequest(t *testing.T) {
	t.Parallel()

	handler := newCORSTestHandler(t, CORSConfig{
		AllowedOrigins: []string{"http://localhost:3000"},
		AllowedMethods: []string{"GET", "POST", "OPTIONS"},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/orders", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:3000" {
		t.Fatalf("Access-Control-Allow-Origin = %q", got)
	}
	if got := rec.Header().Get("Vary"); got != "Origin" {
		t.Fatalf("Vary = %q, want Origin", got)
	}
}

func TestCORSDisallowedOriginOnNormalRequest(t *testing.T) {
	t.Parallel()

	handler := newCORSTestHandler(t, CORSConfig{
		AllowedOrigins: []string{"http://localhost:3000"},
		AllowedMethods: []string{"GET", "POST", "OPTIONS"},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/orders", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want empty", got)
	}
}

func TestCORSAllowedPreflightReturns204(t *testing.T) {
	t.Parallel()

	downstreamCalled := false
	mw, err := NewCORS(CORSConfig{
		AllowedOrigins: []string{"http://localhost:3000"},
		AllowedMethods: []string{"get", "post", "options"},
		AllowedHeaders: []string{"Authorization", "Content-Type"},
	})
	if err != nil {
		t.Fatalf("NewCORS() error = %v", err)
	}

	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		downstreamCalled = true
		w.WriteHeader(http.StatusOK)
	}), mw)

	req := httptest.NewRequest(http.MethodOptions, "/api/orders", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "Authorization, Content-Type")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	vary := rec.Header().Values("Vary")
	joined := strings.Join(vary, ",")

	if !strings.Contains(joined, "Origin") ||
		!strings.Contains(joined, "Access-Control-Request-Method") ||
		!strings.Contains(joined, "Access-Control-Request-Headers") {
		t.Fatalf("Vary header missing expected values: %v", vary)
	}

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if downstreamCalled {
		t.Fatal("downstream handler should not be called for preflight")
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:3000" {
		t.Fatalf("Access-Control-Allow-Origin = %q", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Methods"); got != "GET, POST, OPTIONS" {
		t.Fatalf("Access-Control-Allow-Methods = %q", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Headers"); got != "Authorization, Content-Type" {
		t.Fatalf("Access-Control-Allow-Headers = %q", got)
	}
	if got := rec.Header().Get("Access-Control-Max-Age"); got != "3600" {
		t.Fatalf("Access-Control-Max-Age = %q, want 3600", got)
	}
}

func TestCORSDisallowedPreflightReturns403(t *testing.T) {
	t.Parallel()

	handler := newCORSTestHandler(t, CORSConfig{
		AllowedOrigins: []string{"http://localhost:3000"},
		AllowedMethods: []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders: []string{"Authorization", "Content-Type"},
	})

	req := httptest.NewRequest(http.MethodOptions, "/api/orders", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestCORSCredentialsHeaderIncludedWhenEnabled(t *testing.T) {
	t.Parallel()

	handler := newCORSTestHandler(t, CORSConfig{
		AllowedOrigins:   []string{"http://localhost:3000"},
		AllowedMethods:   []string{"GET", "OPTIONS"},
		AllowCredentials: true,
	})

	req := httptest.NewRequest(http.MethodGet, "/api/orders", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("Access-Control-Allow-Credentials = %q, want true", got)
	}
}

func newCORSTestHandler(t *testing.T, cfg CORSConfig) http.Handler {
	t.Helper()

	mw, err := NewCORS(cfg)
	if err != nil {
		t.Fatalf("NewCORS() error = %v", err)
	}

	return Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), mw)
}

func TestCORSPreflightWithDisallowedHeaderReturns403(t *testing.T) {
	t.Parallel()

	handler := newCORSTestHandler(t, CORSConfig{
		AllowedOrigins: []string{"http://localhost:3000"},
		AllowedMethods: []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders: []string{"Authorization"},
	})

	req := httptest.NewRequest(http.MethodOptions, "/api/orders", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "X-Custom-Header")

	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestCORSPreflightWithDisallowedMethodReturns403(t *testing.T) {
	t.Parallel()

	handler := newCORSTestHandler(t, CORSConfig{
		AllowedOrigins: []string{"http://localhost:3000"},
		AllowedMethods: []string{"GET", "OPTIONS"},
	})

	req := httptest.NewRequest(http.MethodOptions, "/api/orders", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "POST")

	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}
