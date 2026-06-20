package middleware

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
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

			now := time.Now()
			allowed, remaining, reset := limiter.check(key, now)
			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(limiter.limit))
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

func (l *rateLimiter) check(key string, now time.Time) (allowed bool, remaining int, reset time.Time) {
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
		// Reset = when the oldest in-window event exits the window.
		if len(keep) > 0 {
			reset = keep[0].Add(l.window)
		} else {
			reset = now.Add(l.window)
		}
		return false, 0, reset
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

	remaining = l.limit - len(keep)
	if len(keep) > 0 {
		reset = keep[0].Add(l.window)
	} else {
		reset = now.Add(l.window)
	}
	return true, remaining, reset
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
