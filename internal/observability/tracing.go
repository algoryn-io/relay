package observability

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"go.opentelemetry.io/contrib/propagators/b3"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"algoryn.io/relay/internal/config"
)

// TracerShutdown is a function that flushes and shuts down the TracerProvider.
type TracerShutdown func(ctx context.Context) error

type exporterFactory func(context.Context, config.TracingConfig) (sdktrace.SpanExporter, error)

type tracingTarget struct {
	provider   trace.TracerProvider
	propagator propagation.TextMapPropagator
	shutdown   TracerShutdown

	mu      sync.Mutex
	active  int
	retired bool
	drained chan struct{}
	once    sync.Once

	shutdownOnce sync.Once
	shutdownErr  error
}

func (t *tracingTarget) acquire() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.retired {
		return false
	}
	t.active++
	return true
}

func (t *tracingTarget) release() {
	t.mu.Lock()
	t.active--
	if t.retired && t.active == 0 {
		t.once.Do(func() { close(t.drained) })
	}
	t.mu.Unlock()
}

func (t *tracingTarget) closeDrained(ctx context.Context) error {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	t.retired = true
	if t.active == 0 {
		t.once.Do(func() { close(t.drained) })
	}
	t.mu.Unlock()
	select {
	case <-t.drained:
	case <-ctx.Done():
		// Preserve eventual cleanup even when the caller's bounded drain expires.
		// The retired target rejects new leases, so this goroutine finishes after
		// the last request that already held it releases its span.
		cleanupCtx := context.WithoutCancel(ctx)
		go func() {
			<-t.drained
			_ = t.shutdownProvider(cleanupCtx)
		}()
		return ctx.Err()
	}
	return t.shutdownProvider(ctx)
}

func (t *tracingTarget) shutdownProvider(ctx context.Context) error {
	t.shutdownOnce.Do(func() {
		if t.shutdown != nil {
			t.shutdownErr = t.shutdown(ctx)
		}
	})
	return t.shutdownErr
}

// TracingHandle atomically selects the provider used by new requests. Retired
// providers remain alive until every request/span that acquired them finishes.
type TracingHandle struct {
	current atomic.Pointer[tracingTarget]
	factory exporterFactory
}

func newTracingHandle(ctx context.Context, cfg config.TracingConfig, fallbackServiceName string, factory exporterFactory) (*TracingHandle, error) {
	target, err := buildTracingTarget(ctx, cfg, fallbackServiceName, factory)
	if err != nil {
		return nil, err
	}
	handle := &TracingHandle{factory: factory}
	handle.current.Store(target)
	return handle, nil
}

func NewTracingHandle(ctx context.Context, cfg config.TracingConfig, fallbackServiceName string) (*TracingHandle, error) {
	return newTracingHandle(ctx, cfg, fallbackServiceName, buildExporter)
}

func (h *TracingHandle) prepare(ctx context.Context, cfg config.TracingConfig, fallbackServiceName string) (*tracingTarget, error) {
	return buildTracingTarget(ctx, cfg, fallbackServiceName, h.factory)
}

func (h *TracingHandle) acquire() *tracingTarget {
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

func (h *TracingHandle) swap(next *tracingTarget) *tracingTarget {
	return h.current.Swap(next)
}

func (h *TracingHandle) Close(ctx context.Context) error {
	if h == nil {
		return nil
	}
	return h.current.Swap(nil).closeDrained(ctx)
}

// InitTracing configures the global OpenTelemetry TracerProvider and TextMapPropagator.
// Returns a shutdown function that must be called on process exit to flush spans.
// When cfg.Enabled is false a no-op provider is installed and the shutdown is a no-op.
func InitTracing(ctx context.Context, cfg config.TracingConfig, fallbackServiceName string) (TracerShutdown, error) {
	target, err := buildTracingTarget(ctx, cfg, fallbackServiceName, buildExporter)
	if err != nil {
		return nil, err
	}
	otel.SetTracerProvider(target.provider)
	otel.SetTextMapPropagator(target.propagator)
	return target.shutdown, nil
}

func buildTracingTarget(
	ctx context.Context,
	cfg config.TracingConfig,
	fallbackServiceName string,
	factory exporterFactory,
) (*tracingTarget, error) {
	propagator := propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
		b3.New(b3.WithInjectEncoding(b3.B3MultipleHeader)),
	)
	if !cfg.Enabled {
		return &tracingTarget{
			provider:   noop.NewTracerProvider(),
			propagator: propagator,
			shutdown:   func(context.Context) error { return nil },
			drained:    make(chan struct{}),
		}, nil
	}

	svcName := strings.TrimSpace(cfg.ServiceName)
	if svcName == "" {
		svcName = strings.TrimSpace(fallbackServiceName)
	}
	if svcName == "" {
		svcName = "relay"
	}

	res, err := resource.New(ctx,
		resource.WithTelemetrySDK(),
		resource.WithHost(),
		resource.WithFromEnv(),
		resource.WithAttributes(semconv.ServiceName(svcName)),
	)
	if err != nil {
		return nil, fmt.Errorf("tracing resource: %w", err)
	}

	exp, err := factory(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("tracing exporter: %w", err)
	}

	sampleRate := cfg.SampleRate
	if sampleRate == 0 && !cfg.SampleRateSet {
		sampleRate = 1.0
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(sampleRate))),
	)

	return &tracingTarget{
		provider:   tp,
		propagator: propagator,
		shutdown:   tp.Shutdown,
		drained:    make(chan struct{}),
	}, nil
}

func buildExporter(ctx context.Context, cfg config.TracingConfig) (sdktrace.SpanExporter, error) {
	exporter := strings.ToLower(strings.TrimSpace(cfg.Exporter))
	endpoint := strings.TrimSpace(cfg.Endpoint)

	switch exporter {
	case "otlp_grpc", "":
		opts := []otlptracegrpc.Option{otlptracegrpc.WithInsecure()}
		if endpoint != "" {
			opts = append(opts, otlptracegrpc.WithEndpoint(endpoint))
		}
		return otlptracegrpc.New(ctx, opts...)

	case "otlp_http":
		opts := []otlptracehttp.Option{otlptracehttp.WithInsecure()}
		if endpoint != "" {
			opts = append(opts, otlptracehttp.WithEndpoint(endpoint))
		}
		return otlptracehttp.New(ctx, opts...)

	case "stdout":
		return stdouttrace.New(stdouttrace.WithPrettyPrint())

	default:
		return nil, fmt.Errorf("unknown exporter %q", exporter)
	}
}
