package router

import (
	"net/http"
	"net/url"
	"strconv"
	"testing"

	"algoryn.io/relay/internal/config"
)

// benchRouter builds a router with n exact routes, n prefix routes, and a few
// predicate-constrained routes, approximating a realistic routing table.
func benchRouter(b *testing.B, n int) *Router {
	b.Helper()
	routes := make(map[string]config.RouteRuntime, 2*n+2)
	for i := 0; i < n; i++ {
		name := "exact" + strconv.Itoa(i)
		routes[name] = config.RouteRuntime{
			Name: name, Path: "/api/" + strconv.Itoa(i), Methods: []string{http.MethodGet, http.MethodPost},
			MethodSet: map[string]struct{}{http.MethodGet: {}, http.MethodPost: {}}, BackendName: "b",
		}
		pname := "prefix" + strconv.Itoa(i)
		routes[pname] = config.RouteRuntime{
			Name: pname, PathPrefix: "/svc/" + strconv.Itoa(i), Methods: []string{http.MethodGet},
			MethodSet: map[string]struct{}{http.MethodGet: {}}, BackendName: "b",
		}
	}
	routes["host"] = config.RouteRuntime{
		Name: "host", Path: "/data", Methods: []string{http.MethodGet}, MethodSet: map[string]struct{}{http.MethodGet: {}},
		HostSet: map[string]struct{}{"api.example.com": {}}, Specificity: 100, BackendName: "b",
	}
	routes["canary"] = config.RouteRuntime{
		Name: "canary", Path: "/data", Methods: []string{http.MethodGet}, MethodSet: map[string]struct{}{http.MethodGet: {}},
		HeaderMatch: map[string]string{"X-Canary": "true"}, QueryMatch: map[string]string{"v": "2"}, Specificity: 3, BackendName: "b",
	}
	r, err := New(&config.RuntimeConfig{Routes: routes})
	if err != nil {
		b.Fatalf("New() error = %v", err)
	}
	return r
}

func benchRequest(method, path, host, rawQuery string, hdr http.Header) *http.Request {
	if hdr == nil {
		hdr = http.Header{}
	}
	return &http.Request{Method: method, URL: &url.URL{Path: path, RawQuery: rawQuery}, Host: host, Header: hdr}
}

func BenchmarkMatchExact(b *testing.B) {
	r := benchRouter(b, 100)
	req := benchRequest(http.MethodGet, "/api/50", "", "", nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := r.Match(req); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMatchPrefix(b *testing.B) {
	r := benchRouter(b, 100)
	req := benchRequest(http.MethodGet, "/svc/50/resource/123", "", "", nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := r.Match(req); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMatchHostAndHeaderPredicates(b *testing.B) {
	r := benchRouter(b, 100)
	hdr := http.Header{}
	hdr.Set("X-Canary", "true")
	req := benchRequest(http.MethodGet, "/data", "api.example.com", "v=2", hdr)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := r.Match(req); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMatchNotFound(b *testing.B) {
	r := benchRouter(b, 100)
	req := benchRequest(http.MethodGet, "/nope/nothing/here", "", "", nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = r.Match(req)
	}
}
