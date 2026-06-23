package middleware

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

// redisCheckTimeout bounds a single Redis rate-limit call. If Redis is slow or
// unreachable (e.g. a black-holed network), the call fails fast and the limiter
// fails open instead of stalling the request for the full dial timeout.
const redisCheckTimeout = 100 * time.Millisecond

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

const (
	// memoryStoreShards splits the bucket map into independently-locked shards so
	// requests for different keys don't serialize on one global mutex.
	memoryStoreShards = 256
	// memoryPruneInterval is how often the background sweeper removes stale
	// buckets, keeping pruning off the request hot path.
	memoryPruneInterval = time.Minute
)

type memoryShard struct {
	mu      sync.Mutex
	buckets map[string][]time.Time
}

type memoryStore struct {
	salt      []byte
	shards    []*memoryShard
	maxWindow atomic.Int64 // largest window (ns) seen; drives the pruner cutoff

	stop     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

func newMemoryStore() (*memoryStore, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate rate limit salt: %w", err)
	}
	s := &memoryStore{
		salt:   salt,
		shards: make([]*memoryShard, memoryStoreShards),
		stop:   make(chan struct{}),
	}
	for i := range s.shards {
		s.shards[i] = &memoryShard{buckets: make(map[string][]time.Time)}
	}
	s.wg.Add(1)
	go s.pruneLoop()
	return s, nil
}

func (s *memoryStore) HashKey(key string) string {
	mac := hmac.New(sha256.New, s.salt)
	_, _ = mac.Write([]byte(key))
	return hex.EncodeToString(mac.Sum(nil))
}

// shardFor selects the shard for a key via FNV-1a hashing.
func (s *memoryStore) shardFor(key string) *memoryShard {
	var h uint32 = 2166136261
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= 16777619
	}
	return s.shards[h%uint32(len(s.shards))]
}

func (s *memoryStore) Check(_ context.Context, key string, limit int, window time.Duration, now time.Time) (bool, int, time.Time, error) {
	if w := int64(window); w > s.maxWindow.Load() {
		s.maxWindow.Store(w) // best-effort; only used to size the prune cutoff
	}
	cutoff := now.Add(-window)

	sh := s.shardFor(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()

	events := sh.buckets[key]
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
		sh.buckets[key] = keep
		var reset time.Time
		if len(keep) > 0 {
			reset = keep[0].Add(window)
		} else {
			reset = now.Add(window)
		}
		return false, 0, reset, nil
	}

	keep = append(keep, now)
	sh.buckets[key] = keep

	remaining := limit - len(keep)
	var reset time.Time
	if len(keep) > 0 {
		reset = keep[0].Add(window)
	} else {
		reset = now.Add(window)
	}
	return true, remaining, reset, nil
}

// pruneLoop periodically removes buckets whose newest event is older than the
// largest window seen, bounding memory for high-cardinality keyspaces (e.g.
// per-IP) without touching the request path.
func (s *memoryStore) pruneLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(memoryPruneInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
			s.pruneOnce(time.Now())
		}
	}
}

func (s *memoryStore) pruneOnce(now time.Time) {
	w := time.Duration(s.maxWindow.Load())
	if w <= 0 {
		return
	}
	cutoff := now.Add(-w)
	for _, sh := range s.shards {
		sh.mu.Lock()
		for k, ts := range sh.buckets {
			if len(ts) == 0 || !ts[len(ts)-1].After(cutoff) {
				delete(sh.buckets, k)
			}
		}
		sh.mu.Unlock()
	}
}

// Close stops the background pruner. Safe to call multiple times.
func (s *memoryStore) Close() error {
	s.stopOnce.Do(func() { close(s.stop) })
	s.wg.Wait()
	return nil
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
	closer io.Closer // underlying client to close on shutdown/reload; nil in tests
	seq    atomic.Int64
}

func newRedisStore(rawURL string) (*redisStore, error) {
	opts, err := redis.ParseURL(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse redis URL: %w", err)
	}
	c := redis.NewClient(opts)
	return &redisStore{client: c, closer: c}, nil
}

// newRedisStoreFromClient creates a redisStore from an existing Cmdable.
// Used in tests to inject miniredis.
func newRedisStoreFromClient(c redis.Cmdable) *redisStore {
	return &redisStore{client: c}
}

// Close releases the underlying Redis client's connection pool. Without this,
// every config reload would leak a pool (and its background goroutines).
func (s *redisStore) Close() error {
	if s.closer != nil {
		return s.closer.Close()
	}
	return nil
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

	ctx, cancel := context.WithTimeout(ctx, redisCheckTimeout)
	defer cancel()

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
