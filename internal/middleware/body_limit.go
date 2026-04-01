package middleware

import (
	"fmt"
	"net/http"
)

type BodyLimitConfig struct {
	MaxBytes int64
}

func NewBodyLimit(cfg BodyLimitConfig) (Middleware, error) {
	if cfg.MaxBytes <= 0 {
		return nil, fmt.Errorf("body limit max_bytes must be greater than 0")
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, cfg.MaxBytes)
			next.ServeHTTP(w, r)
		})
	}, nil
}
