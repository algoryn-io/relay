package router

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"algoryn.io/relay/internal/config"
)

func TestMatchExactPathAndMethod(t *testing.T) {
	t.Parallel()

	r := newTestRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/api/orders", nil)

	route, err := r.Match(req)
	if err != nil {
		t.Fatalf("Match() error = %v", err)
	}
	if route.Name != "orders-route" {
		t.Fatalf("route.Name = %q, want orders-route", route.Name)
	}
	if route.BackendName != "orders-backend" {
		t.Fatalf("route.BackendName = %q, want orders-backend", route.BackendName)
	}
}

func TestMatchUnknownPathReturnsNotFound(t *testing.T) {
	t.Parallel()

	r := newTestRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/unknown", nil)

	_, err := r.Match(req)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Match() error = %v, want error matching %v", err, ErrNotFound)
	}
}

func TestMatchKnownPathWrongMethodReturnsMethodNotAllowed(t *testing.T) {
	t.Parallel()

	r := newTestRouter(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/orders", nil)

	_, err := r.Match(req)
	if !errors.Is(err, ErrMethodNotAllowed) {
		t.Fatalf("Match() error = %v, want error matching %v", err, ErrMethodNotAllowed)
	}
}

func TestNewDuplicateRouteReturnsError(t *testing.T) {
	t.Parallel()

	rt := &config.RuntimeConfig{
		Routes: map[string]config.RouteRuntime{
			"orders-get": {
				Name:        "orders-get",
				Path:        "/api/orders",
				Methods:     []string{http.MethodGet},
				BackendName: "orders-backend",
			},
			"orders-get-duplicate": {
				Name:        "orders-get-duplicate",
				Path:        "/api/orders",
				Methods:     []string{http.MethodGet},
				BackendName: "payments-backend",
			},
		},
	}

	_, err := New(rt)
	if err == nil {
		t.Fatal("New() error = nil, want duplicate route error")
	}
}

func TestMatchLongestPathPrefixWins(t *testing.T) {
	t.Parallel()

	rt := &config.RuntimeConfig{
		Routes: map[string]config.RouteRuntime{
			"v1-route": {
				Name:        "v1-route",
				PathPrefix:  "/v1",
				Methods:     []string{http.MethodGet},
				MethodSet:   methodSet(http.MethodGet),
				BackendName: "api",
			},
			"v1-auth-route": {
				Name:        "v1-auth-route",
				PathPrefix:  "/v1/auth",
				Methods:     []string{http.MethodPost},
				MethodSet:   methodSet(http.MethodPost),
				BackendName: "api",
			},
		},
	}

	r, err := New(rt)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", nil)
	route, err := r.Match(req)
	if err != nil {
		t.Fatalf("Match() error = %v", err)
	}
	if route.Name != "v1-auth-route" {
		t.Fatalf("route.Name = %q, want v1-auth-route", route.Name)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/v1/students", nil)
	route2, err := r.Match(req2)
	if err != nil {
		t.Fatalf("Match() error = %v", err)
	}
	if route2.Name != "v1-route" {
		t.Fatalf("route.Name = %q, want v1-route", route2.Name)
	}
}

func TestMatchCatchallRootPrefix(t *testing.T) {
	t.Parallel()

	rt := &config.RuntimeConfig{
		Routes: map[string]config.RouteRuntime{
			"api-auth": {
				Name:        "api-auth",
				PathPrefix:  "/v1/auth",
				Methods:     []string{http.MethodGet},
				MethodSet:   methodSet(http.MethodGet),
				BackendName: "bff",
			},
			"catchall": {
				Name:        "catchall",
				PathPrefix:  "/",
				Methods:     []string{http.MethodGet},
				MethodSet:   methodSet(http.MethodGet),
				BackendName: "fe",
			},
		},
	}
	r, err := New(rt)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	route, err := r.Match(httptest.NewRequest(http.MethodGet, "/login", nil))
	if err != nil {
		t.Fatalf("Match() error = %v", err)
	}
	if route.Name != "catchall" {
		t.Fatalf("route.Name = %q, want catchall", route.Name)
	}

	route2, err := r.Match(httptest.NewRequest(http.MethodGet, "/", nil))
	if err != nil {
		t.Fatalf("Match() error = %v", err)
	}
	if route2.Name != "catchall" {
		t.Fatalf("route.Name = %q, want catchall for /", route2.Name)
	}

	route3, err := r.Match(httptest.NewRequest(http.MethodGet, "/v1/auth/ping", nil))
	if err != nil {
		t.Fatalf("Match() error = %v", err)
	}
	if route3.Name != "api-auth" {
		t.Fatalf("route.Name = %q, want api-auth (longer prefix wins)", route3.Name)
	}
}

func TestMatchPathPrefixExactSegment(t *testing.T) {
	t.Parallel()

	rt := &config.RuntimeConfig{
		Routes: map[string]config.RouteRuntime{
			"api": {
				Name:        "api",
				PathPrefix:  "/v1",
				Methods:     []string{http.MethodGet},
				MethodSet:   methodSet(http.MethodGet),
				BackendName: "api",
			},
		},
	}
	r, err := New(rt)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, err = r.Match(httptest.NewRequest(http.MethodGet, "/v10/extra", nil))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Match() error = %v, want %v", err, ErrNotFound)
	}
}

func methodSet(methods ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(methods))
	for _, x := range methods {
		m[x] = struct{}{}
	}
	return m
}

func newTestRouter(t *testing.T) *Router {
	t.Helper()

	rt := &config.RuntimeConfig{
		Routes: map[string]config.RouteRuntime{
			"orders-route": {
				Name:        "orders-route",
				Path:        "/api/orders",
				Methods:     []string{http.MethodGet, http.MethodPost},
				BackendName: "orders-backend",
			},
		},
	}

	r, err := New(rt)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	return r
}
