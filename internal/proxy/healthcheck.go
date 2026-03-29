package proxy

import (
	"context"
	"time"
)

type HealthChecker struct {
	registry BackendRegistry
	cfg      HealthCheckConfig
}

type HealthCheckConfig struct {
	Interval time.Duration
	Timeout  time.Duration
	Path     string
}

func NewHealthChecker(registry BackendRegistry, cfg HealthCheckConfig) *HealthChecker {
	return &HealthChecker{
		registry: registry,
		cfg:      cfg,
	}
}

func (h *HealthChecker) Start(ctx context.Context) {
	_, _ = h, ctx
	// TODO: implement periodic health probes with one worker goroutine per backend instance.
}

func (h *HealthChecker) check(name string, instance *Instance) {
	_, _ = name, instance
	// TODO: implement active HTTP healthcheck probe and registry health-state updates.
}
