package middleware

import (
	"context"
	"testing"
	"time"
)

// Test-only shard-aware accessors for the in-memory store.

func (s *memoryStore) hasBucket(key string) bool {
	sh := s.shardFor(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	_, ok := sh.buckets[key]
	return ok
}

func (s *memoryStore) bucketLen(key string) int {
	sh := s.shardFor(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	return len(sh.buckets[key])
}

func (s *memoryStore) seedBucket(key string, ts []time.Time) {
	sh := s.shardFor(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	sh.buckets[key] = ts
}

func TestMemoryStorePruneRemovesStaleBuckets(t *testing.T) {
	t.Parallel()

	store, err := newMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	now := time.Now()
	// One recent key, one stale key; window is 1s.
	store.Check(context.Background(), "fresh", 10, time.Second, now)
	store.seedBucket("stale", []time.Time{now.Add(-time.Hour)})

	// Drive the pruner directly with a "now" past the stale key's window.
	store.pruneOnce(now.Add(2 * time.Second))

	if store.hasBucket("stale") {
		t.Error("stale bucket should have been pruned")
	}
}

func TestMemoryStoreCloseIsIdempotent(t *testing.T) {
	t.Parallel()

	store, err := newMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}
