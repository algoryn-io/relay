package listener

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"algoryn.io/relay/internal/config"
)

// buildServerWithScrapeCIDRs builds a server whose metrics endpoints allow the
// given scrape CIDRs in addition to loopback.
func buildServerWithScrapeCIDRs(t *testing.T, cidrs []string) *Server {
	t.Helper()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(backend.Close)

	rt := &config.RuntimeConfig{
		Routes: map[string]config.RouteRuntime{
			"r": {Name: "r", Path: "/x", Methods: []string{http.MethodGet}, BackendName: "b"},
		},
		Backends: map[string]config.BackendRuntime{
			"b": {Name: "b", Instances: []config.InstanceRuntime{{URL: backend.URL}}},
		},
	}

	cfg := testServerConfig(config.ListenerConfig{
		HTTP:     config.HTTPConfig{Port: 8080},
		Timeouts: config.TimeoutsConfig{Read: 5 * time.Second, Write: 5 * time.Second, Idle: 5 * time.Second},
	})
	cfg.Observability.Prometheus.AllowedCIDRs = cidrs

	server, err := New(cfg, rt, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return server
}

// A peer within a configured scrape CIDR may reach the Prometheus endpoint, while
// a peer outside it is still rejected — enabling in-cluster scraping (e.g. a
// ServiceMonitor) without opening the endpoint to everyone.
func TestServerMetricsAllowlistPermitsConfiguredCIDR(t *testing.T) {
	t.Parallel()

	server := buildServerWithScrapeCIDRs(t, []string{"10.42.0.0/16"})

	inRange := httptest.NewRequest(http.MethodGet, "/_relay/metrics/prometheus", nil)
	inRange.RemoteAddr = "10.42.3.9:5555"
	recIn := httptest.NewRecorder()
	server.ServeHTTP(recIn, inRange)
	if recIn.Code != http.StatusOK {
		t.Fatalf("in-CIDR prometheus status = %d, want 200", recIn.Code)
	}

	outOfRange := httptest.NewRequest(http.MethodGet, "/_relay/metrics/prometheus", nil)
	outOfRange.RemoteAddr = "203.0.113.10:5555"
	recOut := httptest.NewRecorder()
	server.ServeHTTP(recOut, outOfRange)
	if recOut.Code != http.StatusForbidden {
		t.Fatalf("out-of-CIDR prometheus status = %d, want 403", recOut.Code)
	}

	// A spoofed X-Forwarded-For inside the CIDR must not bypass the real-peer gate.
	spoof := httptest.NewRequest(http.MethodGet, "/_relay/metrics/prometheus", nil)
	spoof.RemoteAddr = "203.0.113.10:5555"
	spoof.Header.Set("X-Forwarded-For", "10.42.3.9")
	recSpoof := httptest.NewRecorder()
	server.ServeHTTP(recSpoof, spoof)
	if recSpoof.Code != http.StatusForbidden {
		t.Fatalf("spoofed-XFF prometheus status = %d, want 403", recSpoof.Code)
	}
}

// With no allowlist configured, the endpoints stay loopback-only (secure default).
func TestServerMetricsDefaultLoopbackOnly(t *testing.T) {
	t.Parallel()

	server := buildServerWithScrapeCIDRs(t, nil)

	remote := httptest.NewRequest(http.MethodGet, "/_relay/metrics/prometheus", nil)
	remote.RemoteAddr = "10.42.3.9:5555"
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, remote)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (default must stay loopback-only)", rec.Code)
	}
}
