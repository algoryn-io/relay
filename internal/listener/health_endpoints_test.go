package listener

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"algoryn.io/relay/internal/config"
)

func TestHealthEndpointsAreOpaqueAndLivenessIsConstant(t *testing.T) {
	t.Parallel()
	server := newHealthPolicyServer(t, config.ListenerConfig{})
	if err := server.state.Load().proxy.DrainInstance("payments-db", "http://secret.internal:8080"); err != nil {
		t.Fatal(err)
	}
	if err := server.state.Load().proxy.DrainInstance("public-api", "http://public.internal:8080"); err != nil {
		t.Fatal(err)
	}

	ready := httptest.NewRecorder()
	server.ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/_relay/ready", nil))
	if ready.Code != http.StatusServiceUnavailable {
		t.Fatalf("readiness status = %d, want 503", ready.Code)
	}
	if got := strings.TrimSpace(ready.Body.String()); got != `{"status":"not_ready"}` {
		t.Fatalf("readiness body = %q", got)
	}
	for _, secret := range []string{"payments-db", "secret.internal", "no_healthy_instance"} {
		if strings.Contains(ready.Body.String(), secret) {
			t.Fatalf("public readiness disclosed %q: %s", secret, ready.Body.String())
		}
	}

	live := httptest.NewRecorder()
	server.ServeHTTP(live, httptest.NewRequest(http.MethodGet, "/_relay/health", nil))
	if live.Code != http.StatusOK || strings.TrimSpace(live.Body.String()) != `{"status":"ok"}` {
		t.Fatalf("liveness = %d %q", live.Code, live.Body.String())
	}
}

func TestHealthAccessUsesRealPeerAndBearerToken(t *testing.T) {
	t.Parallel()
	listener := config.ListenerConfig{
		Health: config.HealthEndpointsConfig{Access: config.EndpointAccessConfig{
			AllowedCIDRs:  []string{"10.0.0.0/8"},
			ResolvedToken: "probe-secret",
		}},
	}
	server := newHealthPolicyServer(t, listener)

	spoofed := httptest.NewRequest(http.MethodGet, "/_relay/ready", nil)
	spoofed.RemoteAddr = "203.0.113.9:1234"
	spoofed.Header.Set("X-Forwarded-For", "10.1.2.3")
	spoofed.Header.Set("Authorization", "Bearer probe-secret")
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, spoofed)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("spoofed XFF status = %d, want 403", rec.Code)
	}

	missingToken := httptest.NewRequest(http.MethodGet, "/_relay/ready", nil)
	missingToken.RemoteAddr = "10.1.2.3:1234"
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, missingToken)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing token status = %d, want 401", rec.Code)
	}

	allowed := httptest.NewRequest(http.MethodGet, "/_relay/ready", nil)
	allowed.RemoteAddr = "10.1.2.3:1234"
	allowed.Header.Set("Authorization", "Bearer probe-secret")
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, allowed)
	if rec.Code != http.StatusOK {
		t.Fatalf("allowed status = %d, want 200", rec.Code)
	}
}

func TestReadinessPolicySemanticsAndAdminDetail(t *testing.T) {
	t.Parallel()
	listener := config.ListenerConfig{
		Health: config.HealthEndpointsConfig{Readiness: config.ReadinessPolicyConfig{
			Mode: "critical", CriticalBackends: []string{"payments-db"},
		}},
		Admin: config.AdminConfig{
			AllowedCIDRs:  []string{"10.0.0.0/8"},
			ResolvedToken: "admin-secret",
		},
	}
	server := newHealthPolicyServer(t, listener)
	if err := server.state.Load().proxy.DrainInstance("payments-db", "http://secret.internal:8080"); err != nil {
		t.Fatal(err)
	}

	public := httptest.NewRecorder()
	server.ServeHTTP(public, httptest.NewRequest(http.MethodGet, "/_relay/ready", nil))
	if public.Code != http.StatusServiceUnavailable {
		t.Fatalf("critical readiness = %d, want 503", public.Code)
	}

	spoofed := httptest.NewRequest(http.MethodGet, "/_relay/admin/readiness", nil)
	spoofed.RemoteAddr = "203.0.113.9:1234"
	spoofed.Header.Set("X-Forwarded-For", "10.1.2.3")
	spoofed.Header.Set("Authorization", "Bearer admin-secret")
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, spoofed)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("admin spoof status = %d, want 403", rec.Code)
	}

	detail := httptest.NewRequest(http.MethodGet, "/_relay/admin/readiness", nil)
	detail.RemoteAddr = "10.1.2.3:1234"
	detail.Header.Set("Authorization", "Bearer admin-secret")
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, detail)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin detail status = %d, want 200", rec.Code)
	}
	for _, want := range []string{"payments-db", "secret.internal", "no_healthy_instance", `"status":"not_ready"`} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("admin detail missing %q: %s", want, rec.Body.String())
		}
	}

	server.state.Load().readinessPolicy = config.ReadinessPolicyConfig{Mode: "any"}
	any := httptest.NewRecorder()
	server.ServeHTTP(any, httptest.NewRequest(http.MethodGet, "/_relay/ready", nil))
	if any.Code != http.StatusOK {
		t.Fatalf("any readiness = %d, want 200", any.Code)
	}

	server.state.Load().readinessPolicy = config.ReadinessPolicyConfig{Mode: "all"}
	all := httptest.NewRecorder()
	server.ServeHTTP(all, httptest.NewRequest(http.MethodGet, "/_relay/ready", nil))
	if all.Code != http.StatusServiceUnavailable {
		t.Fatalf("all readiness = %d, want 503", all.Code)
	}
}

func newHealthPolicyServer(t *testing.T, listener config.ListenerConfig) *Server {
	t.Helper()
	listener.HTTP.Port = 8080
	listener.Timeouts = config.TimeoutsConfig{Read: time.Second, Write: time.Second, Idle: time.Second}
	rt := &config.RuntimeConfig{
		Routes: map[string]config.RouteRuntime{},
		Backends: map[string]config.BackendRuntime{
			"payments-db": {
				Name: "payments-db", Strategy: "round_robin",
				Instances: []config.InstanceRuntime{{URL: "http://secret.internal:8080"}},
			},
			"public-api": {
				Name: "public-api", Strategy: "round_robin",
				Instances: []config.InstanceRuntime{{URL: "http://public.internal:8080"}},
			},
		},
		Middleware: map[string]config.MiddlewareRuntime{},
	}
	server, err := New(testServerConfig(listener), rt, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = server.Shutdown(context.Background()) })
	return server
}
