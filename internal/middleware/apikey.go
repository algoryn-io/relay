package middleware

import "net/http"

type APIKeyConfig struct {
	Header string
	Keys   []string
}

func NewAPIKey(cfg APIKeyConfig) Middleware {
	_ = cfg
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// TODO: implement API key lookup and credential matching from configured key set.
			next.ServeHTTP(w, r)
		})
	}
}
