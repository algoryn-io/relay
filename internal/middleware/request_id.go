package middleware

import (
	"net/http"

	"algoryn.io/relay/internal/httpx"
)

func RequestID() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.Header.Get("X-Request-ID")
			if id == "" {
				id = httpx.GenerateRequestID()
			}
			r = httpx.WithRequestID(r, id)
			r.Header.Set("X-Request-ID", id)
			w.Header().Set("X-Request-ID", id)
			next.ServeHTTP(w, r)
		})
	}
}
