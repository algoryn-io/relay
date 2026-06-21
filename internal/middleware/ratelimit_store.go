package middleware

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

// rateLimitStore is the pluggable backend for the sliding-window rate limiter.
// Implementations must be safe for concurrent use.
type rateLimitStore interface {
	// Check records the current request and reports whether it is allowed.
	// Returns (allowed, remaining, reset, error). On store error the
	// implementation should fail open (allowed=true) so a Redis outage does
	// not take down the gateway.
	Check(ctx context.Context, key string, limit int, window time.Duration, now time.Time) (bool, int, time.Time, error)
	// HashKey returns a deterministic, non-reversible representation of an
	// API key for use as a bucket identifier. Memory and Redis implementations
	// differ: memory uses HMAC+random-salt (private to the instance), Redis
	// uses plain SHA-256 so all relay instances share the same bucket name.
	HashKey(key string) string
}

// ──────────────────────────────────────────────────────────────────────────────
// In-process memory store
// ──────────────────────────────────────────────────────────────────────────────

type memoryStore struct {
	salt []byte

	mu      sync.Mutex
	buckets map[string][]time.Time
}

func newMemoryStore() (*memoryStore, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate rate limit salt: %w", err)
	}
	return &memoryStore{salt: salt, buckets: make(map[string][]time.Time)}, nil
}

func (s *memoryStore) HashKey(key string) string {
	mac := hmac.New(sha256.New, s.salt)
	_, _ = mac.Write([]byte(key))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *memoryStore) Check(_ context.Context, key string, limit int, window time.Duration, now time.Time) (bool, int, time.Time, error) {
	cutoff := now.Add(-window)

	s.mu.Lock()
	defer s.mu.Unlock()

	events := s.buckets[key]
	keep := events[:0]
	for _, ts := range events {
		if ts.After(cutoff) {
			keep = append(keep, ts)
		}
	}
	if len(keep) > limit {
		keep = keep[len(keep)-limit:]
	}

	if len(keep) >= limit {
		s.buckets[key] = keep
		var reset time.Time
		if len(keep) > 0 {
			reset = keep[0].Add(window)
		} else {
			reset = now.Add(window)
		}
		return false, 0, reset, nil
	}

	keep = append(keep, now)
	s.buckets[key] = keep

	// Opportunistic pruning when the bucket map grows large.
	if len(s.buckets) > 1024 {
		for k, ts := range s.buckets {
			if len(ts) == 0 || !ts[len(ts)-1].After(cutoff) {
				delete(s.buckets, k)
			}
		}
	}

	remaining := limit - len(keep)
	var reset time.Time
	if len(keep) > 0 {
		reset = keep[0].Add(window)
	} else {
		reset = now.Add(window)
	}
	return true, remaining, reset, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Redis store  (distributed, shared across all relay instances)
// ──────────────────────────────────────────────────────────────────────────────

// slidingWindowScript implements an atomic sliding-window counter in Redis.
//
// KEYS[1]  — rate limit bucket key
// ARGV[1]  — current time in milliseconds
// ARGV[2]  — window size in milliseconds
// ARGV[3]  — maximum allowed requests in the window
// ARGV[4]  — unique member identifier for this request
//
// Returns: {allowed (1/0), remaining, reset_time_ms}
var slidingWindowScript = redis.NewScript(`
local key    = KEYS[1]
local now    = tonumber(ARGV[1])
local win    = tonumber(ARGV[2])
local limit  = tonumber(ARGV[3])
local member = ARGV[4]
local cutoff = now - win

redis.call('ZREMRANGEBYSCORE', key, '-inf', cutoff)
local count = redis.call('ZCARD', key)

if count >= limit then
  local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
  local oldest_ms = tonumber(oldest[2]) or now
  return {0, 0, oldest_ms + win}
end

redis.call('ZADD', key, now, member)
redis.call('PEXPIRE', key, win)

local remaining = limit - count - 1
local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
local oldest_ms = tonumber(oldest[2]) or now
return {1, remaining, oldest_ms + win}
`)

type redisStore struct {
	client redis.Cmdable
	seq    atomic.Int64
}

func newRedisStore(rawURL string) (*redisStore, error) {
	opts, err := redis.ParseURL(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse redis URL: %w", err)
	}
	return &redisStore{client: redis.NewClient(opts)}, nil
}

// newRedisStoreFromClient creates a redisStore from an existing Cmdable.
// Used in tests to inject miniredis.
func newRedisStoreFromClient(c redis.Cmdable) *redisStore {
	return &redisStore{client: c}
}

// HashKey uses plain SHA-256 so that all relay instances produce the same
// bucket name for a given API key (required for shared Redis counters).
func (s *redisStore) HashKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}

func (s *redisStore) Check(ctx context.Context, key string, limit int, window time.Duration, now time.Time) (bool, int, time.Time, error) {
	nowMs := now.UnixMilli()
	windowMs := window.Milliseconds()
	member := fmt.Sprintf("%d:%d", nowMs, s.seq.Add(1))

	res, err := slidingWindowScript.Run(ctx, s.client,
		[]string{key},
		nowMs, windowMs, limit, member,
	).Slice()
	if err != nil {
		// Fail open: a Redis error allows the request rather than taking
		// down the gateway.
		return true, 0, now.Add(window), fmt.Errorf("redis rate limit check: %w", err)
	}

	if len(res) != 3 {
		return true, 0, now.Add(window), fmt.Errorf("redis script returned %d values, want 3", len(res))
	}

	allowed := asInt64(res[0]) == 1
	remaining := int(asInt64(res[1]))
	resetMs := asInt64(res[2])
	return allowed, remaining, time.UnixMilli(resetMs), nil
}

func asInt64(v interface{}) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case int:
		return int64(x)
	case float64:
		return int64(x)
	}
	return 0
}
