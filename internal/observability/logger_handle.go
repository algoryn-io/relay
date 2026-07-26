package observability

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"

	"algoryn.io/relay/internal/config"
)

type loggerFactory func(config.LogsConfig) (*slog.Logger, io.Closer, error)

type loggerTarget struct {
	logger *slog.Logger
	closer io.Closer

	mu      sync.Mutex
	active  int
	retired bool
	drained *sync.Cond
}

func newLoggerTarget(logger *slog.Logger, closer io.Closer) *loggerTarget {
	target := &loggerTarget{logger: logger, closer: closer}
	target.drained = sync.NewCond(&target.mu)
	return target
}

func (t *loggerTarget) acquire() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.retired {
		return false
	}
	t.active++
	return true
}

func (t *loggerTarget) release() {
	t.mu.Lock()
	t.active--
	if t.retired && t.active == 0 {
		t.drained.Broadcast()
	}
	t.mu.Unlock()
}

func (t *loggerTarget) closeDrained() error {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	t.retired = true
	for t.active != 0 {
		t.drained.Wait()
	}
	t.mu.Unlock()
	if t.closer != nil {
		return t.closer.Close()
	}
	return nil
}

// LoggerHandle owns a stable slog.Logger whose destination, format, rotation,
// and level can be replaced atomically. A replaced writer is closed only after
// all records that acquired it have completed.
type LoggerHandle struct {
	current atomic.Pointer[loggerTarget]
	logger  *slog.Logger
	factory loggerFactory
}

type loggerOperation struct {
	attrs []slog.Attr
	group string
}

type swappingHandler struct {
	handle     *LoggerHandle
	operations []loggerOperation
}

func newLoggerHandle(cfg config.LogsConfig, factory loggerFactory) (*LoggerHandle, error) {
	logger, closer, err := factory(cfg)
	if err != nil {
		return nil, err
	}
	handle := &LoggerHandle{factory: factory}
	handle.current.Store(newLoggerTarget(logger, closer))
	handle.logger = slog.New(&swappingHandler{handle: handle})
	return handle, nil
}

func NewLoggerHandle(cfg config.LogsConfig) (*LoggerHandle, error) {
	return newLoggerHandle(cfg, NewAccessLogger)
}

func (h *LoggerHandle) Logger() *slog.Logger {
	if h == nil || h.logger == nil {
		return slog.Default()
	}
	return h.logger
}

func (h *LoggerHandle) prepare(cfg config.LogsConfig) (*loggerTarget, error) {
	logger, closer, err := h.factory(cfg)
	if err != nil {
		return nil, err
	}
	return newLoggerTarget(logger, closer), nil
}

func (h *LoggerHandle) swap(next *loggerTarget) *loggerTarget {
	return h.current.Swap(next)
}

func (h *LoggerHandle) Close() error {
	if h == nil {
		return nil
	}
	return h.current.Swap(nil).closeDrained()
}

func (h *LoggerHandle) acquire() *loggerTarget {
	for {
		target := h.current.Load()
		if target == nil {
			return nil
		}
		if target.acquire() {
			return target
		}
	}
}

func (h *swappingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	// The target can change between slog's Enabled and Handle calls. Returning
	// true here and enforcing the active target's level in Handle prevents a
	// record admitted by the old level from leaking through the new one.
	return h.handle.current.Load() != nil
}

func (h *swappingHandler) Handle(ctx context.Context, record slog.Record) error {
	target := h.handle.acquire()
	if target == nil {
		return nil
	}
	defer target.release()
	handler := h.replay(target.logger.Handler())
	if !handler.Enabled(ctx, record.Level) {
		return nil
	}
	return handler.Handle(ctx, record)
}

func (h *swappingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	operations := append([]loggerOperation(nil), h.operations...)
	operations = append(operations, loggerOperation{attrs: append([]slog.Attr(nil), attrs...)})
	return &swappingHandler{handle: h.handle, operations: operations}
}

func (h *swappingHandler) WithGroup(name string) slog.Handler {
	operations := append([]loggerOperation(nil), h.operations...)
	operations = append(operations, loggerOperation{group: name})
	return &swappingHandler{handle: h.handle, operations: operations}
}

func (h *swappingHandler) replay(handler slog.Handler) slog.Handler {
	for _, operation := range h.operations {
		if operation.group != "" {
			handler = handler.WithGroup(operation.group)
		} else {
			handler = handler.WithAttrs(operation.attrs)
		}
	}
	return handler
}
