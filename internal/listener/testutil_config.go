package listener

import (
	"time"

	"algoryn.io/relay/internal/config"
)

func testServerConfig(listener config.ListenerConfig) *config.Config {
	return &config.Config{
		Listener: listener,
		Observability: config.ObservabilityConfig{
			Metrics: config.MetricsConfig{FlushInterval: 30 * time.Second},
		},
	}
}
