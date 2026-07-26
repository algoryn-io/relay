package router

import (
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"testing"

	"algoryn.io/relay/internal/config"
)

// FuzzMatch feeds arbitrary request attributes to the router's Match and asserts
// it never panics and always returns either a route (with nil error) or one of
// the known sentinel errors. The router is built once from a representative set
// of routes covering exact/prefix paths and host/header/query predicates.
func FuzzMatch(f *testing.F) {
	globRe, err := config.CompilePathGlob("/files/**")
	if err != nil {
		f.Fatalf("CompilePathGlob() error = %v", err)
	}
	regexRe := regexp.MustCompile(`^/re/.*$`)

	r, err := New(&config.RuntimeConfig{Routes: map[string]config.RouteRuntime{
		"exact":    {Name: "exact", Path: "/api/orders", Methods: []string{http.MethodGet, http.MethodPost}, BackendName: "b"},
		"prefix":   {Name: "prefix", PathPrefix: "/v1", Methods: []string{http.MethodGet}, BackendName: "b"},
		"host":     {Name: "host", Path: "/data", Methods: []string{http.MethodGet}, HostSet: map[string]struct{}{"api.example.com": {}}, Specificity: 100, BackendName: "b"},
		"header":   {Name: "header", Path: "/svc", Methods: []string{http.MethodGet}, HeaderMatch: map[string]string{"X-Canary": "true"}, Specificity: 1, BackendName: "b"},
		"query":    {Name: "query", Path: "/q", Methods: []string{http.MethodGet}, QueryMatch: map[string]string{"v": "2"}, Specificity: 1, BackendName: "b"},
		"glob":     {Name: "glob", PathGlob: "/files/**", PathGlobRe: globRe, PatternRank: config.PathGlobLiteralLen("/files/**"), Methods: []string{http.MethodGet}, BackendName: "b"},
		"regex":    {Name: "regex", PathRegex: regexRe.String(), PathRegexRe: regexRe, PatternRank: len(regexRe.String()), Methods: []string{http.MethodGet}, BackendName: "b"},
		"grpc":     {Name: "grpc", Path: "/demo.Greeter/SayHello", GRPC: true, GRPCService: "demo.Greeter", GRPCMethod: "SayHello", Methods: []string{http.MethodPost}, BackendName: "b"},
		"catchall": {Name: "catchall", PathPrefix: "/", Methods: []string{http.MethodGet}, BackendName: "b"},
	}})
	if err != nil {
		f.Fatalf("New() error = %v", err)
	}

	f.Add("GET", "/api/orders", "api.example.com", "X-Canary", "true", "v=2")
	f.Add("POST", "/v1/users", "", "", "", "")
	f.Add("", "", "", "", "", "")
	f.Add("GET", "/svc", "other.host:8443", "X-Canary", "false", "")

	f.Fuzz(func(t *testing.T, method, path, host, hdrName, hdrVal, rawQuery string) {
		req := &http.Request{
			Method: method,
			URL:    &url.URL{Path: path, RawQuery: rawQuery},
			Host:   host,
			Header: http.Header{},
		}
		if hdrName != "" {
			req.Header.Set(hdrName, hdrVal)
		}

		route, err := r.Match(req)
		switch {
		case err == nil:
			if route == nil {
				t.Fatal("Match returned nil route with nil error")
			}
		case errors.Is(err, ErrNotFound), errors.Is(err, ErrMethodNotAllowed):
			// expected sentinels
		default:
			t.Fatalf("Match returned unexpected error: %v", err)
		}
	})
}
