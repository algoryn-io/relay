package proxy

// bulkhead limits the number of concurrent in-flight requests toward a backend.
// When the concurrency limit is reached, Acquire returns false immediately
// (fail fast — no queuing). Callers must call Release exactly once after a
// successful Acquire.
type bulkhead struct {
	sem chan struct{}
}

func newBulkhead(maxConcurrent int) *bulkhead {
	return &bulkhead{sem: make(chan struct{}, maxConcurrent)}
}

// Acquire claims a concurrency slot. Returns false when the bulkhead is full.
func (b *bulkhead) Acquire() bool {
	select {
	case b.sem <- struct{}{}:
		return true
	default:
		return false
	}
}

// Release frees a concurrency slot previously claimed by Acquire.
func (b *bulkhead) Release() {
	<-b.sem
}

// InFlight returns the number of currently occupied slots.
func (b *bulkhead) InFlight() int {
	return len(b.sem)
}

// Limit returns the maximum allowed concurrency.
func (b *bulkhead) Limit() int {
	return cap(b.sem)
}
