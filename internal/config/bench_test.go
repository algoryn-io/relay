package config

import (
	"strconv"
	"testing"
	"time"
)

// benchConfig builds an in-memory Config with n routes/backends to exercise the
// validation + runtime-build path used on every hot reload.
func benchConfig(n int) *Config {
	c := &Config{
		Listener: ListenerConfig{
			HTTP:     HTTPConfig{Port: 8080},
			Timeouts: TimeoutsConfig{Read: 30 * time.Second, Write: 30 * time.Second, Idle: 60 * time.Second},
		},
	}
	for i := 0; i < n; i++ {
		id := strconv.Itoa(i)
		c.Routes = append(c.Routes, RouteConfig{
			Name:    "route" + id,
			Backend: "backend" + id,
			Match:   MatchConfig{Path: "/api/" + id, Methods: []string{"GET", "POST"}},
		})
		c.Backends = append(c.Backends, BackendConfig{
			Name:      "backend" + id,
			Strategy:  "round_robin",
			Instances: []InstanceConfig{{URL: "http://localhost:9001"}},
		})
	}
	return c
}

func BenchmarkValidate(b *testing.B) {
	c := benchConfig(100)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := c.Validate(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkBuildRuntime(b *testing.B) {
	c := benchConfig(100)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := BuildRuntime(c); err != nil {
			b.Fatal(err)
		}
	}
}
