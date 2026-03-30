package observability

import (
	"net/http"

	"algoryn.io/relay/internal/middleware"
)

func NewMetricsMiddleware(metrics *Metrics, routeName string) middleware.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rec, duration := observeRequest(next, w, r)

			if metrics != nil {
				metrics.Record(routeName, rec.Status(), duration)
			}
		})
	}
}
