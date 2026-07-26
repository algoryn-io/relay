package middleware

import (
	"fmt"
	"io"
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
	// FailOpen permits a request when the backing store fails. It defaults to
	// false: rate limiting must not silently vanish during a Redis outage.
	FailOpen bool
	// MemoryMaxBuckets strictly caps in-process key cardinality.
	MemoryMaxBuckets int
	// MemoryBucketTTL expires idle buckets. It must be at least Window so
	// cleanup cannot reset a still-active sliding window.
	MemoryBucketTTL time.Duration
	// MemoryCleanupInterval controls the single store-wide cleanup loop.
	MemoryCleanupInterval time.Duration
	Metrics               RateLimitMetrics
	Events                RateLimitOperationalEvents
	ObserverKey           string
}

// RateLimitMetrics intentionally exposes only aggregate values: bucket keys
// are never metric labels, avoiding a second cardinality problem.
type RateLimitMetrics interface {
	AddRateLimitMemoryBuckets(delta int)
	RecordRateLimitMemoryEviction()
}

// RateLimitOperationalEvents is implemented outside this package to avoid an
// observability dependency cycle.
type RateLimitOperationalEvents interface {
	RecordRateLimitRedisResult(source string, success, failOpen bool)
	RecordRateLimitFailOpenBypass()
}

type rateLimiter struct {
	limit       int
	window      time.Duration
	by          string
	header      string
	store       rateLimitStore
	failOpen    bool
	redis       bool
	events      RateLimitOperationalEvents
	observerKey string
}

// NewRateLimit returns a sliding-window rate limit middleware. The returned
// io.Closer releases store resources (the in-memory pruner goroutine or the
// Redis connection pool) and must be closed when the middleware is discarded
// (e.g. on config reload). It is nil when the store holds no resources.
func NewRateLimit(cfg RateLimitConfig) (Middleware, io.Closer, error) {
	if cfg.Strategy == "" {
		cfg.Strategy = SlidingWindow
	}
	if cfg.Strategy != SlidingWindow {
		return nil, nil, fmt.Errorf("unsupported rate limit strategy %q", cfg.Strategy)
	}
	if cfg.Limit <= 0 {
		return nil, nil, fmt.Errorf("rate limit must be greater than 0")
	}
	if cfg.Window <= 0 {
		return nil, nil, fmt.Errorf("rate limit window must be greater than 0")
	}
	if cfg.MemoryMaxBuckets == 0 {
		cfg.MemoryMaxBuckets = defaultMemoryMaxBuckets
	}
	if cfg.MemoryBucketTTL == 0 {
		cfg.MemoryBucketTTL = cfg.Window
	}
	if cfg.MemoryCleanupInterval == 0 {
		cfg.MemoryCleanupInterval = defaultMemoryCleanupInterval
	}
	if strings.TrimSpace(cfg.By) == "" {
		cfg.By = "ip"
	}
	switch cfg.By {
	case "ip", "route", "api_key":
	default:
		return nil, nil, fmt.Errorf("unsupported rate limit key %q", cfg.By)
	}
	if cfg.By == "api_key" && strings.TrimSpace(cfg.Header) == "" {
		cfg.Header = "X-API-Key"
	}

	var store rateLimitStore
	switch strings.ToLower(strings.TrimSpace(cfg.Store)) {
	case "redis":
		if strings.TrimSpace(cfg.RedisURL) == "" {
			return nil, nil, fmt.Errorf("redis_url is required when store is redis")
		}
		rs, err := newRedisStore(cfg.RedisURL)
		if err != nil {
			return nil, nil, fmt.Errorf("create redis store: %w", err)
		}
		store = rs
	case "", "memory":
		if cfg.MemoryMaxBuckets <= 0 {
			return nil, nil, fmt.Errorf("memory_max_buckets must be greater than 0")
		}
		if cfg.MemoryBucketTTL < cfg.Window {
			return nil, nil, fmt.Errorf("memory_bucket_ttl must be at least the rate limit window")
		}
		if cfg.MemoryCleanupInterval <= 0 {
			return nil, nil, fmt.Errorf("memory_cleanup_interval must be greater than 0")
		}
		ms, err := newMemoryStoreWithOptions(memoryStoreOptions{
			maxBuckets:      cfg.MemoryMaxBuckets,
			bucketTTL:       cfg.MemoryBucketTTL,
			cleanupInterval: cfg.MemoryCleanupInterval,
			metrics:         cfg.Metrics,
		})
		if err != nil {
			return nil, nil, err
		}
		store = ms
	default:
		return nil, nil, fmt.Errorf("unsupported rate limit store %q", cfg.Store)
	}

	mw, err := newRateLimitWithStore(cfg, store)
	if err != nil {
		if c, ok := store.(io.Closer); ok {
			_ = c.Close()
		}
		return nil, nil, err
	}
	closer, _ := store.(io.Closer)
	return mw, closer, nil
}

// newRateLimitWithStore creates the middleware using an already-constructed
// store. Used internally and in tests to inject stores (e.g. miniredis).
func newRateLimitWithStore(cfg RateLimitConfig, store rateLimitStore) (Middleware, error) {
	rl := &rateLimiter{
		limit:       cfg.Limit,
		window:      cfg.Window,
		by:          cfg.By,
		header:      cfg.Header,
		store:       store,
		failOpen:    cfg.FailOpen,
		redis:       strings.EqualFold(strings.TrimSpace(cfg.Store), "redis") || isRedisStore(store),
		events:      cfg.Events,
		observerKey: cfg.ObserverKey,
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := rl.keyFromRequest(r)
			if key == "" {
				key = "unknown"
			}

			now := time.Now()
			allowed, remaining, reset, err := rl.store.Check(r.Context(), key, rl.limit, rl.window, now)
			if rl.redis && rl.events != nil {
				rl.events.RecordRateLimitRedisResult(rl.observerKey, err == nil, rl.failOpen)
			}
			if err != nil && !rl.failOpen {
				httpx.WriteError(w, http.StatusServiceUnavailable, "rate_limit_unavailable")
				return
			}
			if err != nil && rl.failOpen && rl.events != nil {
				rl.events.RecordRateLimitFailOpenBypass()
			}

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

func isRedisStore(store rateLimitStore) bool {
	_, ok := store.(*redisStore)
	return ok
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
