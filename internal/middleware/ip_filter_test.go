package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIPFilterAllowListMatchPasses(t *testing.T) {
	t.Parallel()

	mw := mustIPFilter(t, IPFilterConfig{
		Allow: []string{"10.0.0.1"},
	})
	called := false
	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}), mw)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !called {
		t.Fatal("expected downstream handler to be called")
	}
}

func TestIPFilterAllowListNoMatchBlocked(t *testing.T) {
	t.Parallel()

	mw := mustIPFilter(t, IPFilterConfig{
		Allow: []string{"10.0.0.1"},
	})
	called := false
	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}), mw)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.2:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if called {
		t.Fatal("downstream handler should not be called for blocked IP")
	}
}

func TestIPFilterDenyListMatchBlocked(t *testing.T) {
	t.Parallel()

	mw := mustIPFilter(t, IPFilterConfig{
		Deny: []string{"1.2.3.4"},
	})
	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), mw)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "1.2.3.4:1000"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestIPFilterDenyListNoMatchPasses(t *testing.T) {
	t.Parallel()

	mw := mustIPFilter(t, IPFilterConfig{
		Deny: []string{"1.2.3.4"},
	})
	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), mw)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "1.2.3.5:1000"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestIPFilterCIDRSupport(t *testing.T) {
	t.Parallel()

	mw := mustIPFilter(t, IPFilterConfig{
		Allow: []string{"192.168.1.0/24"},
	})
	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), mw)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.55:3000"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestIPFilterAllowThenDenyPrecedence(t *testing.T) {
	t.Parallel()

	mw := mustIPFilter(t, IPFilterConfig{
		Allow: []string{"10.0.0.0/8"},
		Deny:  []string{"10.0.0.5"},
	})
	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), mw)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.5:4000"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestIPFilterInvalidConfig(t *testing.T) {
	t.Parallel()

	if _, err := NewIPFilter(IPFilterConfig{}); err == nil {
		t.Fatal("NewIPFilter() error = nil, want error for empty config")
	}
	if _, err := NewIPFilter(IPFilterConfig{
		Allow: []string{"not-an-ip"},
	}); err == nil {
		t.Fatal("NewIPFilter() error = nil, want error for invalid allow entry")
	}
}

func mustIPFilter(t *testing.T, cfg IPFilterConfig) Middleware {
	t.Helper()
	mw, err := NewIPFilter(cfg)
	if err != nil {
		t.Fatalf("NewIPFilter() error = %v", err)
	}
	return mw
}
