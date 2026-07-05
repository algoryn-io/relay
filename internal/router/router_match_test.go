package router

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"algoryn.io/relay/internal/config"
)

func hostSet(hosts ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(hosts))
	for _, h := range hosts {
		m[h] = struct{}{}
	}
	return m
}

func buildRouter(t *testing.T, routes map[string]config.RouteRuntime) *Router {
	t.Helper()
	r, err := New(&config.RuntimeConfig{Routes: routes})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return r
}

func TestMatchHostSpecificRoute(t *testing.T) {
	t.Parallel()

	r := buildRouter(t, map[string]config.RouteRuntime{
		"api": {
			Name:        "api",
			Path:        "/data",
			Methods:     []string{http.MethodGet},
			HostSet:     hostSet("api.example.com"),
			Specificity: 100,
			BackendName: "api-backend",
		},
	})

	// Matching host resolves.
	route, err := r.Match(httptest.NewRequest(http.MethodGet, "http://api.example.com/data", nil))
	if err != nil {
		t.Fatalf("Match(api.example.com) error = %v", err)
	}
	if route.Name != "api" {
		t.Fatalf("route.Name = %q, want api", route.Name)
	}

	// A different host on the same path must not match (404, not 405).
	_, err = r.Match(httptest.NewRequest(http.MethodGet, "http://other.example.com/data", nil))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Match(other host) error = %v, want ErrNotFound", err)
	}

	// Host with an explicit port still matches (port is stripped).
	if _, err := r.Match(httptest.NewRequest(http.MethodGet, "http://api.example.com:8443/data", nil)); err != nil {
		t.Fatalf("Match(host:port) error = %v", err)
	}
}

func TestMatchSamePathDifferentHosts(t *testing.T) {
	t.Parallel()

	r := buildRouter(t, map[string]config.RouteRuntime{
		"tenant-a": {
			Name: "tenant-a", Path: "/x", Methods: []string{http.MethodGet},
			HostSet: hostSet("a.example.com"), Specificity: 100, BackendName: "a",
		},
		"tenant-b": {
			Name: "tenant-b", Path: "/x", Methods: []string{http.MethodGet},
			HostSet: hostSet("b.example.com"), Specificity: 100, BackendName: "b",
		},
	})

	for host, want := range map[string]string{
		"a.example.com": "tenant-a",
		"b.example.com": "tenant-b",
	} {
		route, err := r.Match(httptest.NewRequest(http.MethodGet, "http://"+host+"/x", nil))
		if err != nil {
			t.Fatalf("Match(%s) error = %v", host, err)
		}
		if route.Name != want {
			t.Fatalf("Match(%s) = %q, want %q", host, route.Name, want)
		}
	}
}

func TestMatchHostSpecificFallsBackToCatchAll(t *testing.T) {
	t.Parallel()

	// A host-specific route only allows POST; a catch-all allows GET. A GET for
	// the specific host must fall through to the catch-all rather than 405.
	r := buildRouter(t, map[string]config.RouteRuntime{
		"specific": {
			Name: "specific", Path: "/x", Methods: []string{http.MethodPost},
			HostSet: hostSet("api.example.com"), Specificity: 100, BackendName: "s",
		},
		"catch-all": {
			Name: "catch-all", Path: "/x", Methods: []string{http.MethodGet},
			BackendName: "c",
		},
	})

	route, err := r.Match(httptest.NewRequest(http.MethodGet, "http://api.example.com/x", nil))
	if err != nil {
		t.Fatalf("Match() error = %v", err)
	}
	if route.Name != "catch-all" {
		t.Fatalf("route.Name = %q, want catch-all", route.Name)
	}

	// POST on the specific host prefers the specific route.
	route, err = r.Match(httptest.NewRequest(http.MethodPost, "http://api.example.com/x", nil))
	if err != nil {
		t.Fatalf("Match(POST) error = %v", err)
	}
	if route.Name != "specific" {
		t.Fatalf("route.Name = %q, want specific", route.Name)
	}
}

func TestMatchHeaderPredicate(t *testing.T) {
	t.Parallel()

	r := buildRouter(t, map[string]config.RouteRuntime{
		"canary": {
			Name: "canary", Path: "/svc", Methods: []string{http.MethodGet},
			HeaderMatch: map[string]string{"X-Canary": "true"}, Specificity: 1, BackendName: "canary",
		},
		"stable": {
			Name: "stable", Path: "/svc", Methods: []string{http.MethodGet}, BackendName: "stable",
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/svc", nil)
	req.Header.Set("X-Canary", "true")
	route, err := r.Match(req)
	if err != nil {
		t.Fatalf("Match(canary) error = %v", err)
	}
	if route.Name != "canary" {
		t.Fatalf("route.Name = %q, want canary", route.Name)
	}

	// Without the header, the stable route serves.
	route, err = r.Match(httptest.NewRequest(http.MethodGet, "/svc", nil))
	if err != nil {
		t.Fatalf("Match(stable) error = %v", err)
	}
	if route.Name != "stable" {
		t.Fatalf("route.Name = %q, want stable", route.Name)
	}
}

func TestMatchQueryPredicate(t *testing.T) {
	t.Parallel()

	r := buildRouter(t, map[string]config.RouteRuntime{
		"v2": {
			Name: "v2", Path: "/api", Methods: []string{http.MethodGet},
			QueryMatch: map[string]string{"version": "2"}, Specificity: 1, BackendName: "v2",
		},
		"v1": {
			Name: "v1", Path: "/api", Methods: []string{http.MethodGet}, BackendName: "v1",
		},
	})

	route, err := r.Match(httptest.NewRequest(http.MethodGet, "/api?version=2", nil))
	if err != nil {
		t.Fatalf("Match(version=2) error = %v", err)
	}
	if route.Name != "v2" {
		t.Fatalf("route.Name = %q, want v2", route.Name)
	}

	route, err = r.Match(httptest.NewRequest(http.MethodGet, "/api?version=9", nil))
	if err != nil {
		t.Fatalf("Match(version=9) error = %v", err)
	}
	if route.Name != "v1" {
		t.Fatalf("route.Name = %q, want v1", route.Name)
	}
}

func TestMatchPrefixHostPredicate(t *testing.T) {
	t.Parallel()

	r := buildRouter(t, map[string]config.RouteRuntime{
		"admin": {
			Name: "admin", PathPrefix: "/v1", Methods: []string{http.MethodGet},
			HostSet: hostSet("admin.example.com"), Specificity: 100, BackendName: "admin",
		},
		"public": {
			Name: "public", PathPrefix: "/v1", Methods: []string{http.MethodGet}, BackendName: "public",
		},
	})

	route, err := r.Match(httptest.NewRequest(http.MethodGet, "http://admin.example.com/v1/users", nil))
	if err != nil {
		t.Fatalf("Match(admin) error = %v", err)
	}
	if route.Name != "admin" {
		t.Fatalf("route.Name = %q, want admin", route.Name)
	}

	route, err = r.Match(httptest.NewRequest(http.MethodGet, "http://www.example.com/v1/users", nil))
	if err != nil {
		t.Fatalf("Match(public) error = %v", err)
	}
	if route.Name != "public" {
		t.Fatalf("route.Name = %q, want public", route.Name)
	}
}

func TestNewAllowsSamePathDifferentHosts(t *testing.T) {
	t.Parallel()

	_, err := New(&config.RuntimeConfig{Routes: map[string]config.RouteRuntime{
		"a": {Name: "a", Path: "/x", Methods: []string{http.MethodGet}, HostSet: hostSet("a.com"), Specificity: 100, BackendName: "a"},
		"b": {Name: "b", Path: "/x", Methods: []string{http.MethodGet}, HostSet: hostSet("b.com"), Specificity: 100, BackendName: "b"},
	}})
	if err != nil {
		t.Fatalf("New() error = %v, want nil (different hosts are not duplicates)", err)
	}
}
