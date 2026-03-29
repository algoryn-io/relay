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
