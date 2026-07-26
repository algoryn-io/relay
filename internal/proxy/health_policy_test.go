package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"algoryn.io/relay/internal/config"
)

func TestHealthCheckPolicyMethodHeadersStatusAndBody(t *testing.T) {
	t.Parallel()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodOptions || r.Header.Get("X-Probe-Token") != "relay" {
			http.Error(w, "bad probe", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	p := newTestProxy(t, map[string]config.BackendRuntime{
		"api": {
			Name:     "api",
			Strategy: "round_robin",
			HealthCheck: config.HealthCheckConfig{
				Path:           "/ready",
				Method:         http.MethodOptions,
				Interval:       20 * time.Millisecond,
				Timeout:        time.Second,
				Headers:        map[string]string{"X-Probe-Token": "relay"},
				ExpectedStatus: config.ExpectedStatusConfig{List: []int{200, 204}},
			},
			Instances: []config.InstanceRuntime{{URL: upstream.URL}},
		},
	})
	waitForHealthState(t, p, "api", []bool{true})
}

func TestHealthCheckBodyMatcherIsBounded(t *testing.T) {
	t.Parallel()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ready-but-too-large"))
	}))
	defer upstream.Close()

	p := newTestProxy(t, map[string]config.BackendRuntime{
		"api": {
			Name:     "api",
			Strategy: "round_robin",
			HealthCheck: config.HealthCheckConfig{
				Path:         "/ready",
				Interval:     20 * time.Millisecond,
				Timeout:      time.Second,
				Body:         config.BodyMatcherConfig{Contains: "ready"},
				MaxBodyBytes: 5,
			},
			Instances: []config.InstanceRuntime{{URL: upstream.URL}},
		},
	})
	waitForHealthState(t, p, "api", []bool{false})
}

func TestHealthBodyMatchers(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		matcher config.BodyMatcherConfig
		want    bool
	}{
		{name: "exact", matcher: config.BodyMatcherConfig{Exact: "ready"}, want: true},
		{name: "contains", matcher: config.BodyMatcherConfig{Contains: "ead"}, want: true},
		{name: "regex", matcher: config.BodyMatcherConfig{Regex: `^re[a-z]+$`}, want: true},
		{name: "mismatch", matcher: config.BodyMatcherConfig{Exact: "ok"}, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchHealthBody([]byte("ready"), tc.matcher); got != tc.want {
				t.Fatalf("matchHealthBody() = %v, want %v", got, tc.want)
			}
		})
	}
}
