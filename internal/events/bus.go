package events

import "log/slog"

type Event struct {
	Type    string
	Payload map[string]any
}

type EventBus interface {
	Publish(e Event)
}

type LogEventBus struct {
	logger *slog.Logger
}

var _ EventBus = (*LogEventBus)(nil)

func NewLogEventBus(logger *slog.Logger) *LogEventBus {
	if logger == nil {
		logger = slog.Default()
	}
	return &LogEventBus{logger: logger}
}

func (b *LogEventBus) Publish(e Event) {
	_ = e
	// TODO: implement structured V1 event publication output for all Relay event types.
	b.logger.Info("event published", "type", e.Type)
}
