package middleware

import (
	"net/http"
	"time"
)

type Strategy string

const (
	TokenBucket   Strategy = "token_bucket"
	SlidingWindow Strategy = "sliding_window"
)

type RateLimitConfig struct {
	Strategy Strategy
	Limit    int
	Window   time.Duration
	By       string
}

func NewRateLimit(cfg RateLimitConfig) Middleware {
	_ = cfg
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// TODO: implement token bucket and sliding window request throttling strategies.
			next.ServeHTTP(w, r)
		})
	}
}
