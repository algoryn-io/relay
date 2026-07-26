package middleware

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	defaultCacheMaxEntries            = 1000
	defaultCacheRedisNamespace        = "relay:cache:v1"
	defaultCacheRedisOperationTimeout = 100 * time.Millisecond
)

// cachedResponse is a stored upstream response ready to be replayed to clients.
type cachedResponse struct {
	status    int
	header    http.Header
	body      []byte
	storedAt  time.Time
	expiresAt time.Time
	// public is true when the origin explicitly marked the response shareable
	// (Cache-Control public or s-maxage). Only public entries may be served to an
	// authenticated request; non-public entries are reused for anonymous requests
	// only, so one user's response is never returned to another.
	public bool
}

// cacheStore stores and retrieves cached responses by key. Implementations must
// be safe for concurrent use. Close releases any background resources.
//
// Get returns (nil, nil) on a miss. A non-nil error means the store could not be
// reached or the stored value is corrupt; callers decide fail-open vs fail-closed.
// Delete removes a key (no-op on miss). InvalidateAll drops every entry owned by
// this store instance / namespace.
type cacheStore interface {
	Get(key string) (*cachedResponse, error)
	Set(key string, resp *cachedResponse) error
	Delete(key string) error
	InvalidateAll() error
	Close() error
}

// cacheMemoryStore is an in-process LRU cache with per-entry TTL. Capacity is bounded
// by maxEntries so memory stays flat under load; the least-recently-used entry is
// evicted when the cache is full. Expired entries are dropped lazily on read.
type cacheMemoryStore struct {
	mu       sync.Mutex
	maxItems int
	ll       *list.List // front = most recently used
	items    map[string]*list.Element
	now      func() time.Time
}

type lruItem struct {
	key  string
	resp *cachedResponse
}

func newCacheMemoryStore(maxItems int, now func() time.Time) *cacheMemoryStore {
	if maxItems <= 0 {
		maxItems = defaultCacheMaxEntries
	}
	if now == nil {
		now = time.Now
	}
	return &cacheMemoryStore{
		maxItems: maxItems,
		ll:       list.New(),
		items:    make(map[string]*list.Element, maxItems),
		now:      now,
	}
}

func (s *cacheMemoryStore) Get(key string) (*cachedResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	el, ok := s.items[key]
	if !ok {
		return nil, nil
	}
	item := el.Value.(*lruItem)
	if !item.resp.expiresAt.After(s.now()) {
		// Expired: drop it so it never lingers past its TTL.
		s.removeElement(el)
		return nil, nil
	}
	s.ll.MoveToFront(el)
	return item.resp, nil
}

func (s *cacheMemoryStore) Set(key string, resp *cachedResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if el, ok := s.items[key]; ok {
		el.Value.(*lruItem).resp = resp
		s.ll.MoveToFront(el)
		return nil
	}
	el := s.ll.PushFront(&lruItem{key: key, resp: resp})
	s.items[key] = el
	if s.ll.Len() > s.maxItems {
		if back := s.ll.Back(); back != nil {
			s.removeElement(back)
		}
	}
	return nil
}

func (s *cacheMemoryStore) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if el, ok := s.items[key]; ok {
		s.removeElement(el)
	}
	return nil
}

func (s *cacheMemoryStore) InvalidateAll() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ll.Init()
	s.items = make(map[string]*list.Element, s.maxItems)
	return nil
}

func (s *cacheMemoryStore) removeElement(el *list.Element) {
	s.ll.Remove(el)
	delete(s.items, el.Value.(*lruItem).key)
}

func (s *cacheMemoryStore) Close() error { return nil }

// len reports the number of entries; used in tests.
func (s *cacheMemoryStore) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ll.Len()
}

// cachedResponseWire is the Redis JSON envelope for a cached response.
type cachedResponseWire struct {
	Status    int                 `json:"s"`
	Header    map[string][]string `json:"h"`
	Body      []byte              `json:"b"`
	StoredAt  int64               `json:"t"`
	ExpiresAt int64               `json:"e"`
	Public    bool                `json:"p"`
}

// cacheRedisStore is a shared response cache backed by Redis. Keys are hashed
// under an operator namespace; each value carries its own absolute expiry so TTL
// survives clock skew between Get and Redis PEXPIRE.
type cacheRedisStore struct {
	client    redis.Cmdable
	closer    io.Closer
	namespace string
	timeout   time.Duration
	now       func() time.Time
	maxObject int64
}

func newCacheRedisStore(rawURL, namespace string, timeout time.Duration, maxObject int64, now func() time.Time) (*cacheRedisStore, error) {
	opts, err := redis.ParseURL(strings.TrimSpace(rawURL))
	if err != nil {
		return nil, fmt.Errorf("parse redis URL: %w", err)
	}
	c := redis.NewClient(opts)
	store := newCacheRedisStoreFromClient(c, c, namespace, timeout, maxObject, now)
	ctx, cancel := context.WithTimeout(context.Background(), store.timeout)
	defer cancel()
	if err := c.Ping(ctx).Err(); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("ping redis cache: %w", err)
	}
	return store, nil
}

// newCacheRedisStoreFromClient creates a redis-backed cache from an existing
// Cmdable. Used in tests to inject miniredis.
func newCacheRedisStoreFromClient(c redis.Cmdable, closer io.Closer, namespace string, timeout time.Duration, maxObject int64, now func() time.Time) *cacheRedisStore {
	if timeout <= 0 {
		timeout = defaultCacheRedisOperationTimeout
	}
	if maxObject <= 0 {
		maxObject = defaultCacheMaxObjectBytes
	}
	if now == nil {
		now = time.Now
	}
	namespace = strings.TrimSpace(namespace)
	if namespace == "" {
		namespace = defaultCacheRedisNamespace
	}
	return &cacheRedisStore{
		client:    c,
		closer:    closer,
		namespace: strings.TrimRight(namespace, ":"),
		timeout:   timeout,
		now:       now,
		maxObject: maxObject,
	}
}

func (s *cacheRedisStore) redisKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return s.namespace + ":" + hex.EncodeToString(sum[:])
}

func (s *cacheRedisStore) withTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), s.timeout)
}

func (s *cacheRedisStore) Get(key string) (*cachedResponse, error) {
	ctx, cancel := s.withTimeout()
	defer cancel()

	raw, err := s.client.Get(ctx, s.redisKey(key)).Bytes()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("redis cache get: %w", err)
	}

	var wire cachedResponseWire
	if err := json.Unmarshal(raw, &wire); err != nil {
		// Corrupt entry: drop it so it cannot poison future hits.
		_, _ = s.client.Del(ctx, s.redisKey(key)).Result()
		return nil, fmt.Errorf("redis cache decode: %w", err)
	}
	if int64(len(wire.Body)) > s.maxObject {
		_, _ = s.client.Del(ctx, s.redisKey(key)).Result()
		return nil, nil
	}
	resp := &cachedResponse{
		status:    wire.Status,
		header:    http.Header(wire.Header),
		body:      wire.Body,
		storedAt:  time.Unix(0, wire.StoredAt),
		expiresAt: time.Unix(0, wire.ExpiresAt),
		public:    wire.Public,
	}
	if resp.header == nil {
		resp.header = make(http.Header)
	}
	if !resp.expiresAt.After(s.now()) {
		_, _ = s.client.Del(ctx, s.redisKey(key)).Result()
		return nil, nil
	}
	return resp, nil
}

func (s *cacheRedisStore) Set(key string, resp *cachedResponse) error {
	if resp == nil {
		return nil
	}
	ttl := resp.expiresAt.Sub(s.now())
	if ttl <= 0 {
		return nil
	}
	wire := cachedResponseWire{
		Status:    resp.status,
		Header:    map[string][]string(resp.header),
		Body:      resp.body,
		StoredAt:  resp.storedAt.UnixNano(),
		ExpiresAt: resp.expiresAt.UnixNano(),
		Public:    resp.public,
	}
	payload, err := json.Marshal(wire)
	if err != nil {
		return fmt.Errorf("redis cache encode: %w", err)
	}
	if int64(len(payload)) > s.maxObject+64<<10 {
		// Guard Redis against unexpectedly large envelopes (headers + framing).
		return nil
	}

	ctx, cancel := s.withTimeout()
	defer cancel()
	if err := s.client.Set(ctx, s.redisKey(key), payload, ttl).Err(); err != nil {
		return fmt.Errorf("redis cache set: %w", err)
	}
	return nil
}

func (s *cacheRedisStore) Delete(key string) error {
	ctx, cancel := s.withTimeout()
	defer cancel()
	if err := s.client.Del(ctx, s.redisKey(key)).Err(); err != nil {
		return fmt.Errorf("redis cache delete: %w", err)
	}
	return nil
}

func (s *cacheRedisStore) InvalidateAll() error {
	var cursor uint64
	pattern := s.namespace + ":*"
	for {
		ctx, cancel := s.withTimeout()
		keys, next, err := s.client.Scan(ctx, cursor, pattern, 64).Result()
		if err != nil {
			cancel()
			return fmt.Errorf("redis cache invalidate scan: %w", err)
		}
		if len(keys) > 0 {
			if err := s.client.Del(ctx, keys...).Err(); err != nil {
				cancel()
				return fmt.Errorf("redis cache invalidate delete: %w", err)
			}
		}
		cancel()
		cursor = next
		if cursor == 0 {
			return nil
		}
	}
}

func (s *cacheRedisStore) Close() error {
	if s.closer != nil {
		return s.closer.Close()
	}
	return nil
}

func validateCacheNamespace(namespace string) error {
	if len(namespace) > 64 {
		return fmt.Errorf("cache namespace must be at most 64 characters")
	}
	for _, r := range namespace {
		if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') &&
			!(r >= '0' && r <= '9') && r != '.' && r != '_' && r != '-' && r != ':' {
			return fmt.Errorf("cache namespace contains unsupported character %q", r)
		}
	}
	return nil
}
