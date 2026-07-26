package config

import (
	"strings"
	"testing"
	"time"
)

func TestValidateHealthAndOutlierPolicy(t *testing.T) {
	cfg := &Config{
		Listener: ListenerConfig{
			HTTP:     HTTPConfig{Port: 8080},
			Timeouts: TimeoutsConfig{Read: time.Second, Write: time.Second, Idle: time.Second},
		},
		Routes: []RouteConfig{{
			Name:    "route",
			Backend: "api",
			Match:   MatchConfig{Path: "/", Methods: []string{"GET"}},
		}},
		Backends: []BackendConfig{{
			Name:     "api",
			Strategy: "round_robin",
			HealthCheck: HealthCheckConfig{
				Path:           "/ready",
				Method:         "HEAD",
				Interval:       time.Second,
				Timeout:        time.Second,
				ExpectedStatus: ExpectedStatusConfig{Range: []int{200, 399}},
				Headers:        map[string]string{"X-Probe": "relay"},
				Body:           BodyMatcherConfig{Regex: `ready|degraded`},
				MaxBodyBytes:   4096,
			},
			OutlierDetection: OutlierDetectionConfig{
				Window:               time.Minute,
				ConsecutiveFailures:  3,
				FailureRatePercent:   50,
				MinimumVolume:        10,
				BaseEjectionDuration: time.Second,
				MaxEjectionDuration:  time.Minute,
				MaxEjectionPercent:   50,
				SuccessRecovery:      true,
			},
			Instances: []InstanceConfig{{URL: "https://api.example.com"}},
		}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}
}

func TestValidateRejectsUnsafeHealthPolicy(t *testing.T) {
	cfg := validConfig()
	cfg.Backends[0].HealthCheck = HealthCheckConfig{
		Path:         "/ready",
		Method:       "POST",
		Interval:     time.Second,
		Timeout:      time.Second,
		Headers:      map[string]string{"Connection": "close\r\nX-Evil: yes"},
		Body:         BodyMatcherConfig{Exact: "ok", Regex: ".*"},
		MaxBodyBytes: (1 << 20) + 1,
		ExpectedStatus: ExpectedStatusConfig{
			Exact: 200,
			List:  []int{200},
		},
	}
	cfg.Backends[0].OutlierDetection = OutlierDetectionConfig{
		FailureRatePercent: 50,
		MaxEjectionPercent: 101,
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("invalid policy accepted")
	}
	for _, want := range []string{"method", "hop-by-hop", "control characters", "exactly one", "max_body_bytes", "minimum_volume", "max_ejection_percent"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("validation error %q does not contain %q", err, want)
		}
	}
}

func TestLoadCompactExpectedStatusForms(t *testing.T) {
	for _, tc := range []struct {
		name   string
		value  string
		assert func(t *testing.T, got ExpectedStatusConfig)
	}{
		{name: "exact", value: "204", assert: func(t *testing.T, got ExpectedStatusConfig) {
			if got.Exact != 204 {
				t.Fatalf("exact = %d", got.Exact)
			}
		}},
		{name: "range", value: `"200-299"`, assert: func(t *testing.T, got ExpectedStatusConfig) {
			if len(got.Range) != 2 || got.Range[0] != 200 || got.Range[1] != 299 {
				t.Fatalf("range = %v", got.Range)
			}
		}},
		{name: "list", value: "[200, 204]", assert: func(t *testing.T, got ExpectedStatusConfig) {
			if len(got.List) != 2 || got.List[1] != 204 {
				t.Fatalf("list = %v", got.List)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTempConfig(t, `
backends:
  - name: api
    strategy: round_robin
    health_check:
      expected_status: `+tc.value+`
    instances:
      - url: http://localhost:8080
`)
			cfg, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			tc.assert(t, cfg.Backends[0].HealthCheck.ExpectedStatus)
		})
	}
}
