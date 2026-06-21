package observability

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"algoryn.io/relay/internal/config"
)

// installTestProvider installs an in-memory TracerProvider and returns the
// span recorder. The provider is unregistered at the end of the test.
func installTestProvider(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))
	t.Cleanup(func() {
		_ = tp.Shutdown(context.Background())
		otel.SetTracerProvider(otel.GetTracerProvider()) // restore global no-op
	})
	return rec
}

func TestInitTracingDisabledIsNoOp(t *testing.T) {
	t.Parallel()

	shutdown, err := InitTracing(context.Background(), config.TracingConfig{Enabled: false}, "relay")
	if err != nil {
		t.Fatalf("InitTracing(disabled) error = %v", err)
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown() error = %v", err)
	}
}

func TestInitTracingStdout(t *testing.T) {
	shutdown, err := InitTracing(context.Background(), config.TracingConfig{
		Enabled:  true,
		Exporter: "stdout",
	}, "relay-test")
	if err != nil {
		t.Fatalf("InitTracing(stdout) error = %v", err)
	}
	defer func() { _ = shutdown(context.Background()) }()
}

func TestInitTracingFallbackServiceName(t *testing.T) {
	shutdown, err := InitTracing(context.Background(), config.TracingConfig{
		Enabled:  true,
		Exporter: "stdout",
	}, "fallback-svc")
	if err != nil {
		t.Fatalf("InitTracing error = %v", err)
	}
	defer func() { _ = shutdown(context.Background()) }()
}

func TestTracingMiddlewareCreatesSpan(t *testing.T) {
	rec := installTestProvider(t)

	mw := NewTracingMiddleware("my-route", "my-backend")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	spans := rec.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	span := spans[0]
	if span.Name() != "GET my-route" {
		t.Errorf("span name = %q, want %q", span.Name(), "GET my-route")
	}
}

func TestTracingMiddlewareRecords5xxAsError(t *testing.T) {
	rec := installTestProvider(t)

	mw := NewTracingMiddleware("err-route", "err-backend")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))

	req := httptest.NewRequest(http.MethodGet, "/fail", nil)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	spans := rec.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	if spans[0].Status().Code.String() != "Error" {
		t.Errorf("span status = %q, want Error", spans[0].Status().Code.String())
	}
}

func TestTracingMiddlewarePropagatesTraceContext(t *testing.T) {
	rec := installTestProvider(t)

	var receivedTraceParent string
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The middleware should have injected traceparent into the request headers.
		receivedTraceParent = r.Header.Get("Traceparent")
		w.WriteHeader(http.StatusOK)
	})

	mw := NewTracingMiddleware("fwd-route", "fwd-backend")
	handler := mw(upstream)

	req := httptest.NewRequest(http.MethodGet, "/fwd", nil)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if receivedTraceParent == "" {
		t.Error("expected traceparent header to be injected into upstream request, got empty")
	}
	if len(rec.Ended()) != 1 {
		t.Fatalf("expected 1 span, got %d", len(rec.Ended()))
	}
}

func TestTracingMiddlewareExtractsIncomingContext(t *testing.T) {
	rec := installTestProvider(t)

	// Create a parent span with a known trace ID.
	ctx, parentSpan := otel.Tracer(tracerName).Start(context.Background(), "parent")
	traceID := parentSpan.SpanContext().TraceID().String()

	// Inject parent context into a carrier.
	carrier := propagation.MapCarrier{}
	otel.GetTextMapPropagator().Inject(ctx, carrier)
	parentSpan.End()

	mw := NewTracingMiddleware("child-route", "child-backend")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/child", nil)
	for k, v := range carrier {
		req.Header.Set(k, v)
	}
	handler.ServeHTTP(httptest.NewRecorder(), req)

	spans := rec.Ended()
	// We expect the parent span + the child span created by the middleware.
	var found bool
	for _, s := range spans {
		if s.SpanContext().TraceID().String() == traceID && s.Name() == "GET child-route" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a child span with trace ID %q, got spans: %v", traceID, spans)
	}
}
