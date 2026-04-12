package middleware

import (
	"fmt"
	"log/slog"
	"net/http"

	"algoryn.io/relay/internal/httpx"
)

func Recovery(logger *slog.Logger) Middleware {
	if logger == nil {
		logger = slog.Default()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if recovered := recover(); recovered != nil {
					logger.Error("panic recovered",
						"panic", fmt.Sprint(recovered),
						"path", r.URL.Path,
						"method", r.Method,
					)
					httpx.WriteError(w, http.StatusInternalServerError, "internal_error")
				}
			}()

			next.ServeHTTP(w, r)
		})
	}
}
