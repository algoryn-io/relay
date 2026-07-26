package router

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"algoryn.io/relay/internal/config"
)

func TestMatchPathRegex(t *testing.T) {
	t.Parallel()

	re := regexp.MustCompile(`^/api/v[0-9]+/orders$`)
	r := buildRouter(t, map[string]config.RouteRuntime{
		"regex": {
			Name: "regex", PathRegex: re.String(), PathRegexRe: re, PatternRank: len(re.String()),
			Methods: []string{http.MethodGet}, MethodSet: methodSet(http.MethodGet), BackendName: "b",
		},
	})

	route, err := r.Match(httptest.NewRequest(http.MethodGet, "/api/v2/orders", nil))
	if err != nil {
		t.Fatalf("Match() error = %v", err)
	}
	if route.Name != "regex" {
		t.Fatalf("route.Name = %q, want regex", route.Name)
	}

	_, err = r.Match(httptest.NewRequest(http.MethodGet, "/api/vx/orders", nil))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Match(non-match) error = %v, want ErrNotFound", err)
	}
}

func TestMatchPathGlob(t *testing.T) {
	t.Parallel()

	re, err := config.CompilePathGlob("/api/*/items")
	if err != nil {
		t.Fatalf("CompilePathGlob() error = %v", err)
	}
	r := buildRouter(t, map[string]config.RouteRuntime{
		"glob": {
			Name: "glob", PathGlob: "/api/*/items", PathGlobRe: re, PatternRank: config.PathGlobLiteralLen("/api/*/items"),
			Methods: []string{http.MethodGet}, MethodSet: methodSet(http.MethodGet), BackendName: "b",
		},
	})

	route, err := r.Match(httptest.NewRequest(http.MethodGet, "/api/v1/items", nil))
	if err != nil {
		t.Fatalf("Match() error = %v", err)
	}
	if route.Name != "glob" {
		t.Fatalf("route.Name = %q, want glob", route.Name)
	}

	_, err = r.Match(httptest.NewRequest(http.MethodGet, "/api/v1/extra/items", nil))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Match(multi-segment) error = %v, want ErrNotFound", err)
	}
}

func TestMatchPrecedenceExactPrefixGlobRegex(t *testing.T) {
	t.Parallel()

	globRe, err := config.CompilePathGlob("/svc/**")
	if err != nil {
		t.Fatalf("CompilePathGlob() error = %v", err)
	}
	regexRe := regexp.MustCompile(`^/svc/.*$`)

	r := buildRouter(t, map[string]config.RouteRuntime{
		"exact": {
			Name: "exact", Path: "/svc/orders",
			Methods: []string{http.MethodGet}, MethodSet: methodSet(http.MethodGet), BackendName: "b",
		},
		"prefix": {
			Name: "prefix", PathPrefix: "/svc",
			Methods: []string{http.MethodGet}, MethodSet: methodSet(http.MethodGet), BackendName: "b",
		},
		"glob": {
			Name: "glob", PathGlob: "/svc/**", PathGlobRe: globRe, PatternRank: config.PathGlobLiteralLen("/svc/**"),
			Methods: []string{http.MethodGet}, MethodSet: methodSet(http.MethodGet), BackendName: "b",
		},
		"regex": {
			Name: "regex", PathRegex: regexRe.String(), PathRegexRe: regexRe, PatternRank: len(regexRe.String()),
			Methods: []string{http.MethodGet}, MethodSet: methodSet(http.MethodGet), BackendName: "b",
		},
	})

	route, err := r.Match(httptest.NewRequest(http.MethodGet, "/svc/orders", nil))
	if err != nil {
		t.Fatalf("Match(exact) error = %v", err)
	}
	if route.Name != "exact" {
		t.Fatalf("route.Name = %q, want exact", route.Name)
	}

	// No exact route for /svc/other — longest prefix wins over glob/regex.
	route, err = r.Match(httptest.NewRequest(http.MethodGet, "/svc/other", nil))
	if err != nil {
		t.Fatalf("Match(prefix) error = %v", err)
	}
	if route.Name != "prefix" {
		t.Fatalf("route.Name = %q, want prefix", route.Name)
	}
}

func TestMatchGlobBeatsRegexWhenNoPrefix(t *testing.T) {
	t.Parallel()

	globRe, err := config.CompilePathGlob("/only/**")
	if err != nil {
		t.Fatalf("CompilePathGlob() error = %v", err)
	}
	regexRe := regexp.MustCompile(`^/only/.*$`)

	r := buildRouter(t, map[string]config.RouteRuntime{
		"glob": {
			Name: "glob", PathGlob: "/only/**", PathGlobRe: globRe, PatternRank: config.PathGlobLiteralLen("/only/**"),
			Methods: []string{http.MethodGet}, MethodSet: methodSet(http.MethodGet), BackendName: "b",
		},
		"regex": {
			Name: "regex", PathRegex: regexRe.String(), PathRegexRe: regexRe, PatternRank: len(regexRe.String()),
			Methods: []string{http.MethodGet}, MethodSet: methodSet(http.MethodGet), BackendName: "b",
		},
	})

	route, err := r.Match(httptest.NewRequest(http.MethodGet, "/only/x", nil))
	if err != nil {
		t.Fatalf("Match() error = %v", err)
	}
	if route.Name != "glob" {
		t.Fatalf("route.Name = %q, want glob", route.Name)
	}
}

func TestMatchGRPCServiceAndMethod(t *testing.T) {
	t.Parallel()

	r := buildRouter(t, map[string]config.RouteRuntime{
		"get-order": {
			Name: "get-order", Path: "/orders.v1.Orders/GetOrder",
			GRPC: true, GRPCService: "orders.v1.Orders", GRPCMethod: "GetOrder",
			Methods: []string{http.MethodPost}, MethodSet: methodSet(http.MethodPost), BackendName: "orders",
		},
		"orders-svc": {
			Name: "orders-svc", PathPrefix: "/orders.v1.Orders",
			GRPC: true, GRPCService: "orders.v1.Orders",
			Methods: []string{http.MethodPost}, MethodSet: methodSet(http.MethodPost), BackendName: "orders",
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/orders.v1.Orders/GetOrder", nil)
	req.Header.Set("Content-Type", "application/grpc")
	route, err := r.Match(req)
	if err != nil {
		t.Fatalf("Match(GetOrder) error = %v", err)
	}
	if route.Name != "get-order" {
		t.Fatalf("route.Name = %q, want get-order", route.Name)
	}

	req = httptest.NewRequest(http.MethodPost, "/orders.v1.Orders/ListOrders", nil)
	req.Header.Set("Content-Type", "application/grpc+proto")
	route, err = r.Match(req)
	if err != nil {
		t.Fatalf("Match(ListOrders) error = %v", err)
	}
	if route.Name != "orders-svc" {
		t.Fatalf("route.Name = %q, want orders-svc", route.Name)
	}

	// Same path without gRPC content-type must not match the gRPC route.
	_, err = r.Match(httptest.NewRequest(http.MethodPost, "/orders.v1.Orders/GetOrder", nil))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Match(no content-type) error = %v, want ErrNotFound", err)
	}
}

func TestMatchGRPCDoesNotShadowHTTPExact(t *testing.T) {
	t.Parallel()

	r := buildRouter(t, map[string]config.RouteRuntime{
		"grpc": {
			Name: "grpc", Path: "/demo.Greeter/SayHello",
			GRPC: true, GRPCService: "demo.Greeter", GRPCMethod: "SayHello",
			Methods: []string{http.MethodPost}, MethodSet: methodSet(http.MethodPost), BackendName: "grpc",
		},
		"http": {
			Name: "http", Path: "/demo.Greeter/SayHello",
			Methods: []string{http.MethodGet}, MethodSet: methodSet(http.MethodGet), BackendName: "http",
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/demo.Greeter/SayHello", nil)
	req.Header.Set("Content-Type", "application/grpc")
	route, err := r.Match(req)
	if err != nil {
		t.Fatalf("Match(grpc) error = %v", err)
	}
	if route.Name != "grpc" {
		t.Fatalf("route.Name = %q, want grpc", route.Name)
	}

	route, err = r.Match(httptest.NewRequest(http.MethodGet, "/demo.Greeter/SayHello", nil))
	if err != nil {
		t.Fatalf("Match(http) error = %v", err)
	}
	if route.Name != "http" {
		t.Fatalf("route.Name = %q, want http", route.Name)
	}
}

func TestNewDuplicatePathGlobRejected(t *testing.T) {
	t.Parallel()

	re, err := config.CompilePathGlob("/x/*")
	if err != nil {
		t.Fatalf("CompilePathGlob() error = %v", err)
	}
	_, err = New(&config.RuntimeConfig{Routes: map[string]config.RouteRuntime{
		"a": {Name: "a", PathGlob: "/x/*", PathGlobRe: re, Methods: []string{http.MethodGet}, BackendName: "a"},
		"b": {Name: "b", PathGlob: "/x/*", PathGlobRe: re, Methods: []string{http.MethodGet}, BackendName: "b"},
	}})
	if err == nil {
		t.Fatal("New() error = nil, want duplicate path_glob error")
	}
}
