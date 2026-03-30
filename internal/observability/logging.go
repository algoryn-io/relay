package observability

import (
	"log/slog"
	"net/http"

	"algoryn.io/relay/internal/httpx"
	"algoryn.io/relay/internal/middleware"
)

func NewLoggingMiddleware(logger *slog.Logger, routeName, backendName string) middleware.Middleware {
	if logger == nil {
		logger = slog.Default()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rec, duration := observeRequest(next, w, r)
			attrs := []slog.Attr{
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", rec.Status()),
				slog.Int64("duration_ms", duration.Milliseconds()),
				slog.String("route", routeName),
				slog.String("backend", backendName),
				slog.String("client_ip", httpx.ClientIP(r)),
			}
			if rec.Status() >= http.StatusInternalServerError {
				attrs = append(attrs, slog.String("error", http.StatusText(rec.Status())))
			}

			logger.LogAttrs(r.Context(), slog.LevelInfo, "request", attrs...)
		})
	}
}
