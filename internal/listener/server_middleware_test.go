package listener

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"algoryn.io/relay/internal/config"
	"github.com/golang-jwt/jwt/v5"
)

func TestServerJWTMiddlewareBlocksUnauthenticated(t *testing.T) {
	t.Parallel()

	server := newMiddlewareTestServer(t, 100, time.Minute)
	resp := performRequest(t, server, http.MethodGet, "/secure")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}

func TestServerRateLimitMiddlewareReturns429(t *testing.T) {
	t.Parallel()

	server := newMiddlewareTestServer(t, 1, time.Minute)
	token := mustSignToken(t, "jwt-secret", time.Now().Add(time.Minute))

	req1 := httptest.NewRequest(http.MethodGet, "/limited", nil)
	req1.Header.Set("Authorization", "Bearer "+token)
	req1.RemoteAddr = "10.1.1.9:4444"
	res1 := httptest.NewRecorder()
	server.ServeHTTP(res1, req1)
	if res1.Code != http.StatusOK {
		t.Fatalf("first status = %d, want %d", res1.Code, http.StatusOK)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/limited", nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	req2.RemoteAddr = "10.1.1.9:4444"
	res2 := httptest.NewRecorder()
	server.ServeHTTP(res2, req2)
	if res2.Code != http.StatusTooManyRequests {
		t.Fatalf("second status = %d, want %d", res2.Code, http.StatusTooManyRequests)
	}

	var body map[string]string
	if err := json.NewDecoder(res2.Body).Decode(&body); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if body["error"] != "rate_limited" {
		t.Fatalf("error = %q, want rate_limited", body["error"])
	}
}

func TestServerPublicRouteStillProxies(t *testing.T) {
	t.Parallel()

	server := newMiddlewareTestServer(t, 1, time.Minute)
	resp := performRequest(t, server, http.MethodGet, "/public")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if body["service"] != "gateway-backend" {
		t.Fatalf("service = %q, want gateway-backend", body["service"])
	}
}

func newMiddlewareTestServer(t *testing.T, limit int, window time.Duration) *Server {
	t.Helper()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"service": "gateway-backend",
			"path":    r.URL.Path,
		})
	}))
	t.Cleanup(backend.Close)

	rt := &config.RuntimeConfig{
		Routes: map[string]config.RouteRuntime{
			"secure-route": {
				Name:           "secure-route",
				Path:           "/secure",
				Methods:        []string{http.MethodGet},
				BackendName:    "orders-backend",
				MiddlewareRefs: []string{"jwt-auth"},
			},
			"limited-route": {
				Name:           "limited-route",
				Path:           "/limited",
				Methods:        []string{http.MethodGet},
				BackendName:    "orders-backend",
				MiddlewareRefs: []string{"jwt-auth", "orders-rate-limit"},
			},
			"public-route": {
				Name:        "public-route",
				Path:        "/public",
				Methods:     []string{http.MethodGet},
				BackendName: "orders-backend",
			},
		},
		Backends: map[string]config.BackendRuntime{
			"orders-backend": {
				Name:     "orders-backend",
				Strategy: "round_robin",
				Instances: []config.InstanceRuntime{
					{URL: backend.URL},
				},
			},
		},
		Middleware: map[string]config.MiddlewareRuntime{
			"jwt-auth": {
				Name: "jwt-auth",
				Type: "jwt",
				Config: config.MiddlewareSettingsConfig{
					Secret: "jwt-secret",
					Header: "Authorization",
				},
			},
			"orders-rate-limit": {
				Name: "orders-rate-limit",
				Type: "rate_limit",
				Config: config.MiddlewareSettingsConfig{
					Strategy: "sliding_window",
					Limit:    limit,
					Window:   window,
					By:       "ip",
				},
			},
		},
	}

	server, err := New(config.ListenerConfig{
		HTTP: config.HTTPConfig{Port: 8080},
		Timeouts: config.TimeoutsConfig{
			Read:  30 * time.Second,
			Write: 30 * time.Second,
			Idle:  60 * time.Second,
		},
	}, rt, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return server
}

func mustSignToken(t *testing.T, secret string, exp time.Time) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "integration-user",
		"exp": exp.Unix(),
	})
	out, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}
	return out
}
