package listener

import "algoryn.io/relay/internal/config"

func testServerConfig(listener config.ListenerConfig) *config.Config {
	return &config.Config{
		Listener: listener,
	}
}
