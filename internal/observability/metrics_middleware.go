package observability

import (
	"net/http"
	"time"

	"algoryn.io/relay/internal/middleware"
)

func NewMetricsMiddleware(metrics *Metrics, routeName string) middleware.Middleware {
	return NewMetricsMiddlewareFabric(metrics, nil, nil, "", routeName)
}

// NewMetricsMiddlewareFabric records in-process metrics and, when dispatcher is non-nil,
// enqueues Fabric protobuf telemetry (MetricSnapshot + RunCompleted-shaped Event) per request.
func NewMetricsMiddlewareFabric(metrics *Metrics, prom *PrometheusCollector, fabric *EventDispatcher, relayServiceName, routeName string) middleware.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			prom.RequestStarted(routeName)
			started := time.Now()
			rec, duration := observeRequest(next, w, r)

			if metrics != nil {
				metrics.Record(routeName, rec.Status(), duration)
			}
			prom.RequestFinished(routeName, r.Method, rec.Status(), duration)

			if fabric != nil {
				snap, evt := BuildRequestFabricTelemetry(
					relayServiceName,
					routeName,
					r.Method,
					r.URL.Path,
					rec.Status(),
					duration,
					started,
				)
				fabric.TryEnqueue(FabricDispatchItem{Snapshot: snap, Event: evt})
			}
		})
	}
}
