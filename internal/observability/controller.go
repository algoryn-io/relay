package observability

import (
	"context"
	"errors"
	"fmt"
	"time"

	"algoryn.io/relay/internal/config"
)

const observabilityDrainTimeout = 30 * time.Second

// Controller owns the stable logging and tracing handles used by the process.
type Controller struct {
	Logging *LoggerHandle
	Tracing *TracingHandle
}

// PreparedConfig contains fully initialized logging and tracing resources that
// are not visible to requests until Apply is called.
type PreparedConfig struct {
	logging *loggerTarget
	tracing *tracingTarget
}

func NewController(ctx context.Context, cfg config.ObservabilityConfig) (*Controller, error) {
	logging, err := NewLoggerHandle(cfg.Logs)
	if err != nil {
		return nil, fmt.Errorf("logging: %w", err)
	}
	tracing, err := NewTracingHandle(ctx, cfg.Tracing, cfg.Fabric.ServiceName)
	if err != nil {
		_ = logging.Close()
		return nil, fmt.Errorf("tracing: %w", err)
	}
	return &Controller{Logging: logging, Tracing: tracing}, nil
}

// Prepare initializes every new sink/exporter without mutating live state.
func (c *Controller) Prepare(ctx context.Context, cfg config.ObservabilityConfig) (*PreparedConfig, error) {
	logging, err := c.Logging.prepare(cfg.Logs)
	if err != nil {
		return nil, fmt.Errorf("logging: %w", err)
	}
	tracing, err := c.Tracing.prepare(ctx, cfg.Tracing, cfg.Fabric.ServiceName)
	if err != nil {
		_ = logging.closeDrained()
		return nil, fmt.Errorf("tracing: %w", err)
	}
	return &PreparedConfig{logging: logging, tracing: tracing}, nil
}

// Apply atomically publishes both prepared handles before draining old
// resources. It cannot fail to publish; returned errors are cleanup warnings.
func (c *Controller) Apply(ctx context.Context, prepared *PreparedConfig) error {
	if prepared == nil || prepared.logging == nil || prepared.tracing == nil {
		return fmt.Errorf("prepared observability config is incomplete")
	}
	oldLogging := c.Logging.swap(prepared.logging)
	oldTracing := c.Tracing.swap(prepared.tracing)
	prepared.logging = nil
	prepared.tracing = nil

	drainCtx, cancel := context.WithTimeout(ctx, observabilityDrainTimeout)
	defer cancel()
	return errors.Join(oldTracing.closeDrained(drainCtx), oldLogging.closeDrained())
}

// Abort closes prepared resources that were never published.
func (p *PreparedConfig) Abort(ctx context.Context) error {
	if p == nil {
		return nil
	}
	err := errors.Join(p.tracing.closeDrained(ctx), p.logging.closeDrained())
	p.tracing = nil
	p.logging = nil
	return err
}

func (c *Controller) Close(ctx context.Context) error {
	if c == nil {
		return nil
	}
	return errors.Join(c.Tracing.Close(ctx), c.Logging.Close())
}
