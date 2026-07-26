package middleware

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testRateLimitMetrics struct {
	buckets   atomic.Int64
	evictions atomic.Int64
}

func (m *testRateLimitMetrics) AddRateLimitMemoryBuckets(delta int) {
	m.buckets.Add(int64(delta))
}

func (m *testRateLimitMetrics) RecordRateLimitMemoryEviction() {
	m.evictions.Add(1)
}

type fakeMemoryTicker struct {
	ch      chan time.Time
	stopped chan struct{}
	once    sync.Once
}

func (t *fakeMemoryTicker) Chan() <-chan time.Time { return t.ch }
func (t *fakeMemoryTicker) Stop() {
	t.once.Do(func() { close(t.stopped) })
}

type fakeMemoryClock struct {
	mu     sync.Mutex
	now    time.Time
	ticker *fakeMemoryTicker
}

func newFakeMemoryClock(now time.Time) *fakeMemoryClock {
	return &fakeMemoryClock{
		now: now,
		ticker: &fakeMemoryTicker{
			ch:      make(chan time.Time, 1),
			stopped: make(chan struct{}),
		},
	}
}

func (c *fakeMemoryClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeMemoryClock) NewTicker(time.Duration) memoryTicker { return c.ticker }

func (c *fakeMemoryClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	now := c.now
	c.mu.Unlock()
	c.ticker.ch <- now
}

func TestMemoryStoreCapacityAndMetrics(t *testing.T) {
	t.Parallel()
	metrics := &testRateLimitMetrics{}
	store := mustMemoryStore(t, memoryStoreOptions{
		maxBuckets:      64,
		bucketTTL:       time.Minute,
		cleanupInterval: time.Minute,
		metrics:         metrics,
	})

	now := time.Unix(1_700_000_000, 0)
	for i := 0; i < 10_000; i++ {
		if _, _, _, err := store.Check(context.Background(), fmt.Sprintf("key-%d", i), 10, time.Minute, now); err != nil {
			t.Fatal(err)
		}
		if got := store.bucketCount.Load(); got > 64 {
			t.Fatalf("bucket count = %d, exceeds capacity 64", got)
		}
	}
	if got := store.bucketCount.Load(); got > 64 {
		t.Fatalf("bucket count = %d, exceeds capacity 64", got)
	}
	if got := metrics.evictions.Load(); got == 0 {
		t.Fatal("evictions = 0, want capacity evictions")
	}
	if got := metrics.buckets.Load(); got != store.bucketCount.Load() {
		t.Fatalf("metric buckets = %d, store count = %d", got, store.bucketCount.Load())
	}
}

func TestMemoryStoreEvictsLeastRecentlyUsedInShard(t *testing.T) {
	t.Parallel()
	store := mustMemoryStore(t, memoryStoreOptions{
		maxBuckets:      512,
		bucketTTL:       time.Minute,
		cleanupInterval: time.Minute,
	})
	keys := keysForSameShard(store, 3)
	now := time.Unix(1_700_000_000, 0)
	for _, key := range keys[:2] {
		_, _, _, _ = store.Check(context.Background(), key, 10, time.Minute, now)
	}
	// Refresh the first key, making the second the deterministic LRU victim.
	_, _, _, _ = store.Check(context.Background(), keys[0], 10, time.Minute, now.Add(time.Second))
	_, _, _, _ = store.Check(context.Background(), keys[2], 10, time.Minute, now.Add(2*time.Second))

	if !store.hasBucket(keys[0]) || !store.hasBucket(keys[2]) {
		t.Fatal("recent buckets were unexpectedly evicted")
	}
	if store.hasBucket(keys[1]) {
		t.Fatal("least recently used bucket was not evicted")
	}
}

func TestMemoryStoreCleanupUsesClockAndCloseStopsLoop(t *testing.T) {
	t.Parallel()
	start := time.Unix(1_700_000_000, 0)
	clock := newFakeMemoryClock(start)
	store := mustMemoryStore(t, memoryStoreOptions{
		maxBuckets:      8,
		bucketTTL:       time.Minute,
		cleanupInterval: time.Second,
		clock:           clock,
	})
	_, _, _, _ = store.Check(context.Background(), "client", 2, time.Minute, start)

	clock.advance(time.Minute)
	deadline := time.Now().Add(time.Second)
	for store.hasBucket("client") && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if store.hasBucket("client") {
		t.Fatal("expired bucket was not removed by cleanup loop")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-clock.ticker.stopped:
	case <-time.After(time.Second):
		t.Fatal("cleanup ticker was not stopped")
	}
}

func TestMemoryStoreConcurrentHighCardinality(t *testing.T) {
	t.Parallel()
	store := mustMemoryStore(t, memoryStoreOptions{
		maxBuckets:      128,
		bucketTTL:       time.Minute,
		cleanupInterval: time.Minute,
	})
	now := time.Unix(1_700_000_000, 0)
	var wg sync.WaitGroup
	for worker := 0; worker < 64; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 2_000; i++ {
				key := fmt.Sprintf("%d-%d", worker, i%512)
				allowed, remaining, _, err := store.Check(context.Background(), key, 100, time.Minute, now.Add(time.Duration(i)))
				if err != nil || !allowed || remaining < 0 {
					t.Errorf("Check(%q) = allowed %v, remaining %d, err %v", key, allowed, remaining, err)
					return
				}
			}
		}(worker)
	}
	wg.Wait()
	if got := store.bucketCount.Load(); got > 128 {
		t.Fatalf("bucket count = %d, exceeds capacity 128", got)
	}
}

func TestMemoryStoreConcurrentClose(t *testing.T) {
	t.Parallel()
	metrics := &testRateLimitMetrics{}
	store, err := newMemoryStoreWithOptions(memoryStoreOptions{
		maxBuckets:      64,
		bucketTTL:       time.Minute,
		cleanupInterval: time.Minute,
		metrics:         metrics,
	})
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for worker := 0; worker < 32; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; ; i++ {
				_, _, _, checkErr := store.Check(
					context.Background(),
					fmt.Sprintf("%d-%d", worker, i%128),
					10,
					time.Minute,
					time.Now(),
				)
				if checkErr != nil {
					return
				}
			}
		}(worker)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if got := store.bucketCount.Load(); got != 0 {
		t.Fatalf("bucket count after Close = %d, want 0", got)
	}
	if got := metrics.buckets.Load(); got != 0 {
		t.Fatalf("bucket metric after Close = %d, want 0", got)
	}
	if _, _, _, err := store.Check(context.Background(), "closed", 1, time.Minute, time.Now()); err == nil {
		t.Fatal("Check after Close error = nil")
	}
}

func mustMemoryStore(t *testing.T, opts memoryStoreOptions) *memoryStore {
	t.Helper()
	store, err := newMemoryStoreWithOptions(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func keysForSameShard(store *memoryStore, count int) []string {
	keys := make([]string, 0, count)
	var target *memoryShard
	for i := 0; len(keys) < count; i++ {
		key := fmt.Sprintf("same-shard-%d", i)
		shard := store.shardFor(key)
		if target == nil {
			target = shard
		}
		if shard == target {
			keys = append(keys, key)
		}
	}
	return keys
}
