package observability

import (
	"log/slog"
	"sync"

	fabricv1 "algoryn.io/fabric/gen/go/fabric/v1"
)

// FabricDispatchItem carries protobuf telemetry from Relay toward Fabric consumers (e.g. Beacon).
// Either or both fields may be set. The worker processes items without blocking HTTP handlers.
type FabricDispatchItem struct {
	Snapshot *fabricv1.MetricSnapshot
	Event    *fabricv1.Event
}

// FabricDispatchHandler receives dequeued items. Implementations must return quickly;
// heavy I/O should spawn its own workers.
type FabricDispatchHandler func(FabricDispatchItem)

// EventDispatcher buffers Fabric telemetry on a channel and processes it in a background goroutine.
type EventDispatcher struct {
	ch      chan FabricDispatchItem
	handler FabricDispatchHandler
	logger  *slog.Logger

	closeOnce sync.Once
	closed    chan struct{}
	done      chan struct{}
}

// NewEventDispatcher starts a processor goroutine. queueSize should be > 0.
func NewEventDispatcher(queueSize int, logger *slog.Logger, handler FabricDispatchHandler) *EventDispatcher {
	if queueSize <= 0 {
		queueSize = 1024
	}
	if handler == nil {
		handler = fabricLogHandler(logger)
	}
	if logger == nil {
		logger = slog.Default()
	}
	d := &EventDispatcher{
		ch:      make(chan FabricDispatchItem, queueSize),
		handler: handler,
		logger:  logger,
		closed:  make(chan struct{}),
		done:    make(chan struct{}),
	}
	go d.loop()
	return d
}

func fabricLogHandler(logger *slog.Logger) FabricDispatchHandler {
	return func(item FabricDispatchItem) {
		if item.Event != nil {
			logger.Debug("fabric event",
				"type", item.Event.GetType().String(),
				"source", item.Event.GetSource(),
			)
		}
		if item.Snapshot != nil {
			logger.Debug("fabric metric snapshot",
				"service", item.Snapshot.GetService(),
				"total", item.Snapshot.GetTotal(),
			)
		}
	}
}

func (d *EventDispatcher) loop() {
	defer close(d.done)
	for item := range d.ch {
		func() {
			defer func() {
				if r := recover(); r != nil {
					d.logger.Error("fabric dispatch handler panic", "recover", r)
				}
			}()
			d.handler(item)
		}()
	}
}

// TryEnqueue forwards an item to the async processor. It never blocks the caller:
// if the buffer is full, the item is dropped and an error is logged.
func (d *EventDispatcher) TryEnqueue(item FabricDispatchItem) {
	select {
	case <-d.closed:
		return
	default:
	}

	select {
	case <-d.closed:
	case d.ch <- item:
	default:
		d.logger.Warn("fabric dispatch queue full; dropping telemetry item")
	}
}

// Close stops accepting new items and waits for the processor to drain the channel.
func (d *EventDispatcher) Close() {
	d.closeOnce.Do(func() {
		close(d.closed)
		close(d.ch)
	})
	<-d.done
}
