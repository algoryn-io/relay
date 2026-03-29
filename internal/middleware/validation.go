package middleware

import "net/http"

type ValidationConfig struct {
	RequiredHeaders []string
	MaxBodyBytes    int64
}

func NewValidation(cfg ValidationConfig) Middleware {
	_ = cfg
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// TODO: implement request header and body-size validation rules for inbound traffic.
			next.ServeHTTP(w, r)
		})
	}
}
