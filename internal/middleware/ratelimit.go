package middleware

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"algoryn.io/relay/internal/httpx"
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
	Header   string
	// Store selects the rate limit backend: "memory" (default) or "redis".
	Store string
	// RedisURL is the Redis connection URL when Store == "redis".
	// Accepts the redis:// and rediss:// schemes.
	RedisURL string
}

type rateLimiter struct {
	limit  int
	window time.Duration
	by     string
	header string
	store  rateLimitStore
}

// NewRateLimit returns a sliding-window rate limit middleware.
func NewRateLimit(cfg RateLimitConfig) (Middleware, error) {
	if cfg.Strategy == "" {
		cfg.Strategy = SlidingWindow
	}
	if cfg.Strategy != SlidingWindow {
		return nil, fmt.Errorf("unsupported rate limit strategy %q", cfg.Strategy)
	}
	if cfg.Limit <= 0 {
		return nil, fmt.Errorf("rate limit must be greater than 0")
	}
	if cfg.Window <= 0 {
		return nil, fmt.Errorf("rate limit window must be greater than 0")
	}
	if strings.TrimSpace(cfg.By) == "" {
		cfg.By = "ip"
	}
	switch cfg.By {
	case "ip", "route", "api_key":
	default:
		return nil, fmt.Errorf("unsupported rate limit key %q", cfg.By)
	}
	if cfg.By == "api_key" && strings.TrimSpace(cfg.Header) == "" {
		cfg.Header = "X-API-Key"
	}

	var store rateLimitStore
	switch strings.ToLower(strings.TrimSpace(cfg.Store)) {
	case "redis":
		if strings.TrimSpace(cfg.RedisURL) == "" {
			return nil, fmt.Errorf("redis_url is required when store is redis")
		}
		rs, err := newRedisStore(cfg.RedisURL)
		if err != nil {
			return nil, fmt.Errorf("create redis store: %w", err)
		}
		store = rs
	default: // "" or "memory"
		ms, err := newMemoryStore()
		if err != nil {
			return nil, err
		}
		store = ms
	}

	return newRateLimitWithStore(cfg, store)
}

// newRateLimitWithStore creates the middleware using an already-constructed
// store. Used internally and in tests to inject stores (e.g. miniredis).
func newRateLimitWithStore(cfg RateLimitConfig, store rateLimitStore) (Middleware, error) {
	rl := &rateLimiter{
		limit:  cfg.Limit,
		window: cfg.Window,
		by:     cfg.By,
		header: cfg.Header,
		store:  store,
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := rl.keyFromRequest(r)
			if key == "" {
				key = "unknown"
			}

			now := time.Now()
			allowed, remaining, reset, _ := rl.store.Check(r.Context(), key, rl.limit, rl.window, now)

			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(rl.limit))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(reset.Unix(), 10))

			if !allowed {
				retryAfter := int(time.Until(reset).Seconds()) + 1
				if retryAfter < 1 {
					retryAfter = 1
				}
				w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
				httpx.WriteError(w, http.StatusTooManyRequests, "rate_limited")
				return
			}

			next.ServeHTTP(w, r)
		})
	}, nil
}

func (l *rateLimiter) keyFromRequest(r *http.Request) string {
	switch l.by {
	case "route":
		return r.Method + ":" + r.URL.Path
	case "api_key":
		key := strings.TrimSpace(r.Header.Get(l.header))
		if key == "" {
			return ""
		}
		return l.store.HashKey(key)
	default:
		return httpx.ClientIP(r)
	}
}
