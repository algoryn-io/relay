package middleware

import (
	"container/list"
	"net/http"
	"sync"
	"time"
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
type cacheStore interface {
	Get(key string) (*cachedResponse, bool)
	Set(key string, resp *cachedResponse)
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
		maxItems = 1000
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

func (s *cacheMemoryStore) Get(key string) (*cachedResponse, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	el, ok := s.items[key]
	if !ok {
		return nil, false
	}
	item := el.Value.(*lruItem)
	if !item.resp.expiresAt.After(s.now()) {
		// Expired: drop it so it never lingers past its TTL.
		s.removeElement(el)
		return nil, false
	}
	s.ll.MoveToFront(el)
	return item.resp, true
}

func (s *cacheMemoryStore) Set(key string, resp *cachedResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if el, ok := s.items[key]; ok {
		el.Value.(*lruItem).resp = resp
		s.ll.MoveToFront(el)
		return
	}
	el := s.ll.PushFront(&lruItem{key: key, resp: resp})
	s.items[key] = el
	if s.ll.Len() > s.maxItems {
		if back := s.ll.Back(); back != nil {
			s.removeElement(back)
		}
	}
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
