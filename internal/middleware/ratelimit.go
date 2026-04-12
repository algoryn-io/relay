package middleware

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
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
}

type rateLimiter struct {
	limit  int
	window time.Duration
	by     string
	header string

	mu      sync.Mutex
	buckets map[string][]time.Time

	apiKeySalt []byte
}

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

	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate rate limit salt: %w", err)
	}

	limiter := &rateLimiter{
		limit:      cfg.Limit,
		window:     cfg.Window,
		by:         cfg.By,
		header:     cfg.Header,
		buckets:    make(map[string][]time.Time),
		apiKeySalt: salt,
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := limiter.keyFromRequest(r)
			if key == "" {
				key = "unknown"
			}

			if !limiter.allow(key, time.Now()) {
				httpx.WriteError(w, http.StatusTooManyRequests, "rate_limited")
				return
			}

			next.ServeHTTP(w, r)
		})
	}, nil
}

func (l *rateLimiter) allow(key string, now time.Time) bool {
	cutoff := now.Add(-l.window)

	l.mu.Lock()
	defer l.mu.Unlock()

	events := l.buckets[key]
	keep := events[:0]
	for _, ts := range events {
		if ts.After(cutoff) {
			keep = append(keep, ts)
		}
	}
	if len(keep) > l.limit {
		keep = keep[len(keep)-l.limit:]
	}
	if len(keep) >= l.limit {
		l.buckets[key] = keep
		return false
	}

	keep = append(keep, now)
	l.buckets[key] = keep

	// Opportunistic pruning to keep memory bounded.
	if len(l.buckets) > 1024 {
		for k, timestamps := range l.buckets {
			if len(timestamps) == 0 || !timestamps[len(timestamps)-1].After(cutoff) {
				delete(l.buckets, k)
			}
		}
	}

	return true
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
		return l.hashAPIKey(key)
	default:
		return httpx.ClientIP(r)
	}
}

func (l *rateLimiter) hashAPIKey(key string) string {
	mac := hmac.New(sha256.New, l.apiKeySalt)
	_, _ = mac.Write([]byte(key))
	return hex.EncodeToString(mac.Sum(nil))
}
