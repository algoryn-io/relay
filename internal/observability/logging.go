package observability

import (
	"log/slog"
	"net/http"

	"algoryn.io/relay/internal/config"
	"algoryn.io/relay/internal/middleware"
)

func NewLoggingMiddleware(logger *slog.Logger, routeName, backendName string) middleware.Middleware {
	return NewLoggingMiddlewareWithConfig(logger, routeName, backendName, config.AccessLogConfig{})
}

func NewLoggingMiddlewareWithConfig(logger *slog.Logger, routeName, backendName string, cfg config.AccessLogConfig) middleware.Middleware {
	if logger == nil {
		logger = slog.Default()
	}
	policy := compileAccessPolicy(cfg)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rec, duration := observeRequest(next, w, r)
			attrs := policy.attrs(r, rec, duration, routeName, backendName)
			logger.LogAttrs(r.Context(), slog.LevelInfo, "request", attrs...)
		})
	}
}
