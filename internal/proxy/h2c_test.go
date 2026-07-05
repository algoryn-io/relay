package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"algoryn.io/relay/internal/config"
)

// newH2CBackend starts a cleartext HTTP/2 (h2c) test server that echoes the
// negotiated protocol major version, so a proxied request can be confirmed to
// have reached the backend over HTTP/2.
func newH2CBackend(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	server.Config.Protocols = protocols
	server.Start()
	t.Cleanup(server.Close)
	return server
}

func TestProxyH2CBackendReachesUpstreamOverHTTP2(t *testing.T) {
	t.Parallel()

	var gotProtoMajor int
	backend := newH2CBackend(t, func(w http.ResponseWriter, r *http.Request) {
		gotProtoMajor = r.ProtoMajor
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("pong"))
	})

	p := newTestProxy(t, map[string]config.BackendRuntime{
		"grpc-backend": {
			Name:      "grpc-backend",
			Protocol:  "h2c",
			Strategy:  "round_robin",
			Instances: []config.InstanceRuntime{{URL: backend.URL}},
		},
	})

	resp := performProxyRequest(t, p, &config.RouteRuntime{BackendName: "grpc-backend"}, http.MethodPost, "/pkg.Service/Method")
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if gotProtoMajor != 2 {
		t.Fatalf("backend saw HTTP/%d, want HTTP/2 (h2c transport not used)", gotProtoMajor)
	}
	if string(body) != "pong" {
		t.Fatalf("body = %q, want pong", body)
	}
}

func TestProxyDefaultBackendUsesHTTP1(t *testing.T) {
	t.Parallel()

	var gotProtoMajor int
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotProtoMajor = r.ProtoMajor
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(backend.Close)

	p := newTestProxy(t, map[string]config.BackendRuntime{
		"http-backend": {
			Name:      "http-backend",
			Strategy:  "round_robin",
			Instances: []config.InstanceRuntime{{URL: backend.URL}},
		},
	})

	resp := performProxyRequest(t, p, &config.RouteRuntime{BackendName: "http-backend"}, http.MethodGet, "/x")
	defer resp.Body.Close()

	if gotProtoMajor != 1 {
		t.Fatalf("default backend saw HTTP/%d, want HTTP/1", gotProtoMajor)
	}
}
