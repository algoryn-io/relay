package observability

import (
	"context"
	"fmt"
	"strings"

	"go.opentelemetry.io/contrib/propagators/b3"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"

	"algoryn.io/relay/internal/config"
)

// TracerShutdown is a function that flushes and shuts down the TracerProvider.
type TracerShutdown func(ctx context.Context) error

// InitTracing configures the global OpenTelemetry TracerProvider and TextMapPropagator.
// Returns a shutdown function that must be called on process exit to flush spans.
// When cfg.Enabled is false a no-op provider is installed and the shutdown is a no-op.
func InitTracing(ctx context.Context, cfg config.TracingConfig, fallbackServiceName string) (TracerShutdown, error) {
	if !cfg.Enabled {
		otel.SetTracerProvider(otel.GetTracerProvider()) // keep whatever is set (no-op default)
		return func(context.Context) error { return nil }, nil
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

	exp, err := buildExporter(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("tracing exporter: %w", err)
	}

	sampleRate := cfg.SampleRate
	if sampleRate <= 0 {
		sampleRate = 1.0
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(sampleRate))),
	)

	// W3C TraceContext + B3 (for compatibility with older services).
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
		b3.New(b3.WithInjectEncoding(b3.B3MultipleHeader)),
	))

	return tp.Shutdown, nil
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
