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
// unreachable (e.g. a black-holed network), the call fails fast instead of
// stalling the request for the full dial timeout.
const redisCheckTimeout = 100 * time.Millisecond

// rateLimitStore is the pluggable backend for the sliding-window rate limiter.
// Implementations must be safe for concurrent use.
type rateLimitStore interface {
	// Check records the current request and reports whether it is allowed.
	// Returns (allowed, remaining, reset, error). The middleware chooses whether
	// an error fails closed (default) or fails open (explicit configuration).
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
	memoryStoreShards            = 256
	defaultMemoryMaxBuckets      = 100_000
	defaultMemoryBucketTTL       = time.Minute
	defaultMemoryCleanupInterval = time.Minute
)

type memoryBucket struct {
	key      string
	events   []time.Time
	lastSeen time.Time
	prev     *memoryBucket
	next     *memoryBucket
}

type memoryShard struct {
	mu       sync.Mutex
	buckets  map[string]*memoryBucket
	head     *memoryBucket
	tail     *memoryBucket
	capacity int
}

type memoryTicker interface {
	Chan() <-chan time.Time
	Stop()
}

type memoryClock interface {
	Now() time.Time
	NewTicker(time.Duration) memoryTicker
}

type realMemoryClock struct{}

func (realMemoryClock) Now() time.Time { return time.Now() }

func (realMemoryClock) NewTicker(d time.Duration) memoryTicker {
	return realMemoryTicker{Ticker: time.NewTicker(d)}
}

type realMemoryTicker struct{ *time.Ticker }

func (t realMemoryTicker) Chan() <-chan time.Time { return t.C }

type memoryStoreOptions struct {
	maxBuckets      int
	bucketTTL       time.Duration
	cleanupInterval time.Duration
	clock           memoryClock
	metrics         RateLimitMetrics
}

type memoryStore struct {
	salt        []byte
	shards      []*memoryShard
	bucketTTL   time.Duration
	clock       memoryClock
	metrics     RateLimitMetrics
	bucketCount atomic.Int64

	stop     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
	closed   atomic.Bool
}

func newMemoryStore() (*memoryStore, error) {
	return newMemoryStoreWithOptions(memoryStoreOptions{
		maxBuckets:      defaultMemoryMaxBuckets,
		bucketTTL:       defaultMemoryBucketTTL,
		cleanupInterval: defaultMemoryCleanupInterval,
	})
}

func newMemoryStoreWithOptions(opts memoryStoreOptions) (*memoryStore, error) {
	if opts.maxBuckets <= 0 {
		return nil, fmt.Errorf("memory rate limit max buckets must be greater than 0")
	}
	if opts.bucketTTL <= 0 {
		return nil, fmt.Errorf("memory rate limit bucket TTL must be greater than 0")
	}
	if opts.cleanupInterval <= 0 {
		return nil, fmt.Errorf("memory rate limit cleanup interval must be greater than 0")
	}
	if opts.clock == nil {
		opts.clock = realMemoryClock{}
	}
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate rate limit salt: %w", err)
	}
	shardCount := memoryStoreShards
	if opts.maxBuckets < shardCount {
		shardCount = opts.maxBuckets
	}
	s := &memoryStore{
		salt:      salt,
		shards:    make([]*memoryShard, shardCount),
		bucketTTL: opts.bucketTTL,
		clock:     opts.clock,
		metrics:   opts.metrics,
		stop:      make(chan struct{}),
	}
	for i := range s.shards {
		capacity := opts.maxBuckets / shardCount
		if i < opts.maxBuckets%shardCount {
			capacity++
		}
		s.shards[i] = &memoryShard{
			buckets:  make(map[string]*memoryBucket, capacity),
			capacity: capacity,
		}
	}
	s.wg.Add(1)
	go s.pruneLoop(opts.cleanupInterval)
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
	return s.shards[uint64(h)%uint64(len(s.shards))]
}

func (s *memoryStore) Check(_ context.Context, key string, limit int, window time.Duration, now time.Time) (bool, int, time.Time, error) {
	if s.closed.Load() {
		return false, 0, now.Add(window), fmt.Errorf("memory rate limit store is closed")
	}
	cutoff := now.Add(-window)

	sh := s.shardFor(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if s.closed.Load() {
		return false, 0, now.Add(window), fmt.Errorf("memory rate limit store is closed")
	}

	bucket := sh.buckets[key]
	if bucket == nil {
		if len(sh.buckets) >= sh.capacity {
			s.removeBucketLocked(sh, sh.tail, true)
		}
		bucket = &memoryBucket{key: key}
		sh.buckets[key] = bucket
		sh.pushFront(bucket)
		s.addBuckets(1)
	} else {
		sh.moveToFront(bucket)
	}
	bucket.lastSeen = now

	events := bucket.events
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
		bucket.events = keep
		var reset time.Time
		if len(keep) > 0 {
			reset = keep[0].Add(window)
		} else {
			reset = now.Add(window)
		}
		return false, 0, reset, nil
	}

	keep = append(keep, now)
	bucket.events = keep

	remaining := limit - len(keep)
	var reset time.Time
	if len(keep) > 0 {
		reset = keep[0].Add(window)
	} else {
		reset = now.Add(window)
	}
	return true, remaining, reset, nil
}

func (s *memoryStore) pruneLoop(interval time.Duration) {
	defer s.wg.Done()
	ticker := s.clock.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case now := <-ticker.Chan():
			s.pruneOnce(now)
		}
	}
}

func (s *memoryStore) pruneOnce(now time.Time) {
	cutoff := now.Add(-s.bucketTTL)
	for _, sh := range s.shards {
		sh.mu.Lock()
		for bucket := sh.tail; bucket != nil && !bucket.lastSeen.After(cutoff); {
			prev := bucket.prev
			s.removeBucketLocked(sh, bucket, false)
			bucket = prev
		}
		// A fake or non-monotonic clock can break LRU time ordering. Scan the
		// remainder as a correctness fallback; normal operation stops above.
		for _, bucket := range sh.buckets {
			if !bucket.lastSeen.After(cutoff) {
				s.removeBucketLocked(sh, bucket, false)
			}
		}
		sh.mu.Unlock()
	}
}

func (s *memoryStore) Close() error {
	s.stopOnce.Do(func() {
		s.closed.Store(true)
		close(s.stop)
		for _, sh := range s.shards {
			sh.mu.Lock()
			n := len(sh.buckets)
			sh.buckets = make(map[string]*memoryBucket)
			sh.head = nil
			sh.tail = nil
			sh.mu.Unlock()
			s.addBuckets(-n)
		}
	})
	s.wg.Wait()
	return nil
}

func (s *memoryStore) removeBucketLocked(sh *memoryShard, bucket *memoryBucket, evicted bool) {
	if bucket == nil {
		return
	}
	delete(sh.buckets, bucket.key)
	sh.remove(bucket)
	s.addBuckets(-1)
	if evicted && s.metrics != nil {
		s.metrics.RecordRateLimitMemoryEviction()
	}
}

func (s *memoryStore) addBuckets(delta int) {
	s.bucketCount.Add(int64(delta))
	if s.metrics != nil {
		s.metrics.AddRateLimitMemoryBuckets(delta)
	}
}

func (sh *memoryShard) pushFront(bucket *memoryBucket) {
	bucket.prev = nil
	bucket.next = sh.head
	if sh.head != nil {
		sh.head.prev = bucket
	} else {
		sh.tail = bucket
	}
	sh.head = bucket
}

func (sh *memoryShard) moveToFront(bucket *memoryBucket) {
	if bucket == sh.head {
		return
	}
	sh.remove(bucket)
	sh.pushFront(bucket)
}

func (sh *memoryShard) remove(bucket *memoryBucket) {
	if bucket.prev != nil {
		bucket.prev.next = bucket.next
	} else {
		sh.head = bucket.next
	}
	if bucket.next != nil {
		bucket.next.prev = bucket.prev
	} else {
		sh.tail = bucket.prev
	}
	bucket.prev = nil
	bucket.next = nil
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
