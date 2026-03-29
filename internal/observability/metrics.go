package observability

import (
	"context"
	"sync"
	"time"

	relayevents "algoryn.io/relay/internal/events"
)

const (
	SampleErrorRate   = 1.0
	SampleSlowRate    = 1.0
	SampleSuccessRate = 0.05
)

type EventBus interface {
	Publish(e relayevents.Event)
}

type Collector struct {
	bus           EventBus
	flushInterval time.Duration
	mu            sync.Mutex
}

func NewCollector(bus EventBus, flushInterval time.Duration) *Collector {
	return &Collector{
		bus:           bus,
		flushInterval: flushInterval,
	}
}

func (c *Collector) Record(routeID string, status int, latencyMs int64) {
	_, _, _ = routeID, status, latencyMs
	// TODO: implement in-memory aggregation and probabilistic sampling for request metrics.
}

func (c *Collector) Start(ctx context.Context) {
	if c.flushInterval <= 0 {
		c.flushInterval = 10 * time.Second
	}
	ticker := time.NewTicker(c.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.flush()
		}
	}
}

func (c *Collector) flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	// TODO: build fabric.MetricSnapshot with Source=metrics.SourceRelay and persist summary to SQLite.
	if c.bus != nil {
		c.bus.Publish(relayevents.Event{
			Type:    "metrics.flush",
			Payload: map[string]any{"source": "relay"},
		})
	}
}
