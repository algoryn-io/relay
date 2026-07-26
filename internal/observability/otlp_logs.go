package observability

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"

	"algoryn.io/relay/internal/config"
)

const (
	defaultOTLPLogQueueSize     = 2048
	defaultOTLPLogBatchSize     = 512
	defaultOTLPLogBatchTimeout  = time.Second
	defaultOTLPLogExportTimeout = 10 * time.Second
)

var otlpLogDrops atomic.Uint64

type otlpLogSink struct {
	provider *sdklog.LoggerProvider
	logger   otellog.Logger
	once     sync.Once
}

func newOTLPLogSink(ctx context.Context, cfg config.OTLPLogsConfig) (*otlpLogSink, error) {
	headers, err := resolveOTLPHeaders(cfg)
	if err != nil {
		return nil, err
	}
	exporter, err := newOTLPLogExporter(ctx, cfg, headers)
	if err != nil {
		return nil, err
	}
	return newOTLPLogSinkWithExporter(ctx, cfg, exporter)
}

func newOTLPLogSinkWithExporter(ctx context.Context, cfg config.OTLPLogsConfig, exporter sdklog.Exporter) (*otlpLogSink, error) {
	queueSize := cfg.QueueSize
	if queueSize <= 0 {
		queueSize = defaultOTLPLogQueueSize
	}
	batchSize := cfg.BatchSize
	if batchSize <= 0 {
		batchSize = defaultOTLPLogBatchSize
	}
	if batchSize > queueSize {
		batchSize = queueSize
	}
	batchTimeout := cfg.BatchTimeout
	if batchTimeout <= 0 {
		batchTimeout = defaultOTLPLogBatchTimeout
	}
	exportTimeout := cfg.ExportTimeout
	if exportTimeout <= 0 {
		exportTimeout = defaultOTLPLogExportTimeout
	}
	processor := newOTLPBatchProcessor(exporter, queueSize, batchSize, batchTimeout, exportTimeout)
	serviceName := strings.TrimSpace(cfg.ServiceName)
	if serviceName == "" {
		serviceName = "relay"
	}
	res, err := resource.New(ctx,
		resource.WithTelemetrySDK(),
		resource.WithHost(),
		resource.WithFromEnv(),
		resource.WithAttributes(semconv.ServiceName(serviceName)),
	)
	if err != nil {
		_ = exporter.Shutdown(ctx)
		return nil, fmt.Errorf("OTLP logs resource: %w", err)
	}
	provider := sdklog.NewLoggerProvider(sdklog.WithResource(res), sdklog.WithProcessor(processor))
	sink := &otlpLogSink{
		provider: provider,
		logger:   provider.Logger("algoryn.io/relay"),
	}
	return sink, nil
}

func newOTLPLogExporter(ctx context.Context, cfg config.OTLPLogsConfig, headers map[string]string) (sdklog.Exporter, error) {
	endpoint := strings.TrimSpace(cfg.Endpoint)
	timeout := cfg.ExportTimeout
	if timeout <= 0 {
		timeout = defaultOTLPLogExportTimeout
	}
	switch strings.ToLower(strings.TrimSpace(cfg.Exporter)) {
	case "", "otlp_grpc":
		opts := []otlploggrpc.Option{otlploggrpc.WithHeaders(headers), otlploggrpc.WithTimeout(timeout)}
		if endpoint != "" {
			if strings.Contains(endpoint, "://") {
				opts = append(opts, otlploggrpc.WithEndpointURL(endpoint))
			} else {
				opts = append(opts, otlploggrpc.WithEndpoint(endpoint))
			}
		}
		if cfg.Insecure {
			opts = append(opts, otlploggrpc.WithInsecure())
		}
		return otlploggrpc.New(ctx, opts...)
	case "otlp_http":
		opts := []otlploghttp.Option{otlploghttp.WithHeaders(headers), otlploghttp.WithTimeout(timeout)}
		if endpoint != "" {
			if strings.Contains(endpoint, "://") {
				opts = append(opts, otlploghttp.WithEndpointURL(endpoint))
			} else {
				opts = append(opts, otlploghttp.WithEndpoint(endpoint))
			}
		}
		if cfg.Insecure {
			opts = append(opts, otlploghttp.WithInsecure())
		}
		return otlploghttp.New(ctx, opts...)
	default:
		return nil, fmt.Errorf("unknown OTLP logs exporter %q", cfg.Exporter)
	}
}

func resolveOTLPHeaders(cfg config.OTLPLogsConfig) (map[string]string, error) {
	headers := make(map[string]string, len(cfg.Headers))
	for key, value := range cfg.Headers {
		headers[key] = value
	}
	raw := strings.TrimSpace(cfg.ResolvedHeaders)
	if raw == "" {
		return headers, nil
	}
	for _, item := range strings.Split(raw, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(item), "=")
		if !ok || strings.TrimSpace(key) == "" {
			return nil, fmt.Errorf("OTLP headers must use comma-separated key=value entries")
		}
		decoded, err := url.QueryUnescape(strings.TrimSpace(value))
		if err != nil {
			return nil, fmt.Errorf("decode OTLP header %q: %w", key, err)
		}
		headers[strings.TrimSpace(key)] = decoded
	}
	return headers, nil
}

func (s *otlpLogSink) enqueue(ctx context.Context, record slog.Record) {
	if s == nil {
		return
	}
	s.logger.Emit(context.WithoutCancel(ctx), toOTelLogRecord(record))
}

func (s *otlpLogSink) Close() error {
	if s == nil {
		return nil
	}
	var closeErr error
	s.once.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), observabilityDrainTimeout)
		defer cancel()
		closeErr = s.provider.Shutdown(ctx)
	})
	return closeErr
}

// otlpBatchProcessor is a bounded, non-blocking Processor with observable
// overflow. Keeping the queue here (rather than in front of the SDK) ensures
// every SDK-side drop increments relay_otlp_log_dropped_total.
type otlpBatchProcessor struct {
	exporter      sdklog.Exporter
	queue         chan sdklog.Record
	flush         chan chan error
	done          chan struct{}
	batchSize     int
	batchTimeout  time.Duration
	exportTimeout time.Duration

	mu      sync.Mutex
	stopped bool
	once    sync.Once
}

func newOTLPBatchProcessor(exporter sdklog.Exporter, queueSize, batchSize int, batchTimeout, exportTimeout time.Duration) *otlpBatchProcessor {
	processor := &otlpBatchProcessor{
		exporter: exporter, queue: make(chan sdklog.Record, queueSize),
		flush: make(chan chan error), done: make(chan struct{}),
		batchSize: batchSize, batchTimeout: batchTimeout, exportTimeout: exportTimeout,
	}
	go processor.run()
	return processor
}

func (p *otlpBatchProcessor) Enabled(context.Context, sdklog.EnabledParameters) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.stopped
}

func (p *otlpBatchProcessor) OnEmit(_ context.Context, record *sdklog.Record) error {
	if record == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stopped {
		return nil
	}
	select {
	case p.queue <- record.Clone():
	default:
		otlpLogDrops.Add(1)
	}
	return nil
}

func (p *otlpBatchProcessor) run() {
	defer close(p.done)
	timer := time.NewTimer(p.batchTimeout)
	defer timer.Stop()
	batch := make([]sdklog.Record, 0, p.batchSize)
	export := func() error {
		if len(batch) == 0 {
			return nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), p.exportTimeout)
		err := p.exporter.Export(ctx, batch)
		cancel()
		batch = batch[:0]
		return err
	}
	report := func(err error) {
		if err != nil {
			otel.Handle(err)
		}
	}
	resetTimer := func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(p.batchTimeout)
	}
	drain := func() bool {
		for len(batch) < p.batchSize {
			select {
			case record, ok := <-p.queue:
				if !ok {
					return false
				}
				batch = append(batch, record)
			default:
				return true
			}
		}
		return true
	}
	for {
		select {
		case record, ok := <-p.queue:
			if !ok {
				report(export())
				return
			}
			batch = append(batch, record)
			if len(batch) >= p.batchSize {
				report(export())
				resetTimer()
			}
		case response := <-p.flush:
			var err error
			open := true
			for {
				open = drain()
				err = errors.Join(err, export())
				if !open || len(p.queue) == 0 {
					break
				}
			}
			err = errors.Join(err, p.exporter.ForceFlush(context.Background()))
			response <- err
			if !open {
				return
			}
			resetTimer()
		case <-timer.C:
			report(export())
			timer.Reset(p.batchTimeout)
		}
	}
}

func (p *otlpBatchProcessor) ForceFlush(ctx context.Context) error {
	response := make(chan error, 1)
	p.mu.Lock()
	if p.stopped {
		p.mu.Unlock()
		return nil
	}
	select {
	case p.flush <- response:
		p.mu.Unlock()
	case <-ctx.Done():
		p.mu.Unlock()
		return ctx.Err()
	}
	select {
	case err := <-response:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *otlpBatchProcessor) Shutdown(ctx context.Context) error {
	p.once.Do(func() {
		p.mu.Lock()
		p.stopped = true
		close(p.queue)
		p.mu.Unlock()
	})
	select {
	case <-p.done:
		return p.exporter.Shutdown(ctx)
	case <-ctx.Done():
		return ctx.Err()
	}
}

func toOTelLogRecord(record slog.Record) otellog.Record {
	var out otellog.Record
	out.SetTimestamp(record.Time)
	out.SetObservedTimestamp(time.Now())
	out.SetBody(otellog.StringValue(record.Message))
	out.SetSeverityText(record.Level.String())
	out.SetSeverity(slogSeverity(record.Level))
	record.Attrs(func(attr slog.Attr) bool {
		appendOTelAttr(&out, "", attr)
		return true
	})
	return out
}

func appendOTelAttr(record *otellog.Record, prefix string, attr slog.Attr) {
	attr.Value = attr.Value.Resolve()
	key := attr.Key
	if prefix != "" {
		key = prefix + "." + key
	}
	if attr.Value.Kind() == slog.KindGroup {
		for _, child := range attr.Value.Group() {
			appendOTelAttr(record, key, child)
		}
		return
	}
	switch attr.Value.Kind() {
	case slog.KindString:
		record.AddAttributes(otellog.String(key, attr.Value.String()))
	case slog.KindBool:
		record.AddAttributes(otellog.Bool(key, attr.Value.Bool()))
	case slog.KindInt64:
		record.AddAttributes(otellog.Int64(key, attr.Value.Int64()))
	case slog.KindUint64:
		value := attr.Value.Uint64()
		if value <= uint64(^uint64(0)>>1) {
			record.AddAttributes(otellog.Int64(key, int64(value)))
		} else {
			record.AddAttributes(otellog.String(key, fmt.Sprint(value)))
		}
	case slog.KindFloat64:
		record.AddAttributes(otellog.Float64(key, attr.Value.Float64()))
	case slog.KindDuration:
		record.AddAttributes(otellog.Int64(key, attr.Value.Duration().Nanoseconds()))
	case slog.KindTime:
		record.AddAttributes(otellog.String(key, attr.Value.Time().Format(time.RFC3339Nano)))
	default:
		record.AddAttributes(otellog.String(key, fmt.Sprint(attr.Value.Any())))
	}
}

func slogSeverity(level slog.Level) otellog.Severity {
	switch {
	case level >= slog.LevelError:
		return otellog.SeverityError
	case level >= slog.LevelWarn:
		return otellog.SeverityWarn
	case level >= slog.LevelInfo:
		return otellog.SeverityInfo
	default:
		return otellog.SeverityDebug
	}
}

type fanoutHandler struct {
	handlers []slog.Handler
}

func (h fanoutHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, handler := range h.handlers {
		if handler.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (h fanoutHandler) Handle(ctx context.Context, record slog.Record) error {
	var errs []error
	for _, handler := range h.handlers {
		if handler.Enabled(ctx, record.Level) {
			errs = append(errs, handler.Handle(ctx, record))
		}
	}
	return errors.Join(errs...)
}

func (h fanoutHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	next := make([]slog.Handler, len(h.handlers))
	for i, handler := range h.handlers {
		next[i] = handler.WithAttrs(attrs)
	}
	return fanoutHandler{handlers: next}
}

func (h fanoutHandler) WithGroup(name string) slog.Handler {
	next := make([]slog.Handler, len(h.handlers))
	for i, handler := range h.handlers {
		next[i] = handler.WithGroup(name)
	}
	return fanoutHandler{handlers: next}
}

type otlpSlogHandler struct {
	sink   *otlpLogSink
	level  slog.Leveler
	attrs  []slog.Attr
	groups []string
}

func (h *otlpSlogHandler) Enabled(_ context.Context, level slog.Level) bool {
	return h.sink != nil && level >= h.level.Level()
}

func (h *otlpSlogHandler) Handle(ctx context.Context, record slog.Record) error {
	if len(h.attrs) != 0 {
		record.AddAttrs(h.attrs...)
	}
	if len(h.groups) != 0 {
		attrs := make([]slog.Attr, 0, record.NumAttrs())
		record.Attrs(func(attr slog.Attr) bool {
			attrs = append(attrs, attr)
			return true
		})
		for i := len(h.groups) - 1; i >= 0; i-- {
			attrs = []slog.Attr{slog.Group(h.groups[i], attrsToAny(attrs)...)}
		}
		record = slog.NewRecord(record.Time, record.Level, record.Message, record.PC)
		record.AddAttrs(attrs...)
	}
	h.sink.enqueue(ctx, record)
	return nil
}

func (h *otlpSlogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	next := *h
	next.attrs = append(append([]slog.Attr(nil), h.attrs...), attrs...)
	return &next
}

func (h *otlpSlogHandler) WithGroup(name string) slog.Handler {
	next := *h
	next.groups = append(append([]string(nil), h.groups...), name)
	return &next
}

func attrsToAny(attrs []slog.Attr) []any {
	values := make([]any, len(attrs))
	for i := range attrs {
		values[i] = attrs[i]
	}
	return values
}
