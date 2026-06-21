package observability

import (
	"fmt"
	"net/http"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"

	"algoryn.io/relay/internal/middleware"
)

const tracerName = "algoryn.io/relay"

// NewTracingMiddleware returns a middleware that creates an OTel span per
// request, propagates trace context to the upstream, and records the outcome.
// When tracing is disabled the global provider is a no-op, so this is safe
// to always register.
func NewTracingMiddleware(routeName, backendName string) middleware.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tracer := otel.Tracer(tracerName)
			propagator := otel.GetTextMapPropagator()

			// Extract any incoming trace context (from the client or an upstream proxy).
			ctx := propagator.Extract(r.Context(), propagation.HeaderCarrier(r.Header))

			spanName := fmt.Sprintf("%s %s", r.Method, routeName)
			ctx, span := tracer.Start(ctx, spanName,
				trace.WithSpanKind(trace.SpanKindServer),
				trace.WithAttributes(
					semconv.HTTPRequestMethodKey.String(r.Method),
					semconv.URLPath(r.URL.Path),
					semconv.ServerAddress(r.Host),
					attribute.String("relay.route", routeName),
					attribute.String("relay.backend", backendName),
				),
			)
			defer span.End()

			// Inject trace context into outgoing request headers so the upstream
			// receives traceparent / b3 headers.
			propagator.Inject(ctx, propagation.HeaderCarrier(r.Header))

			rw := newStatusRecorder(w)
			next.ServeHTTP(rw, r.WithContext(ctx))

			status := rw.Status()
			span.SetAttributes(semconv.HTTPResponseStatusCode(status))
			if status >= 500 {
				span.SetStatus(codes.Error, http.StatusText(status))
			}
		})
	}
}

