package proxy

import (
	"math"
	"sync/atomic"
)

// retryBudget bounds the volume of retries a backend may issue relative to its
// request volume, preventing a failing backend from amplifying its own load
// (a "retry storm"). It is a token bucket: every completed request deposits
// `ratio` tokens (capped at `max`), and every retry withdraws one. When the
// bucket is empty, retries are suppressed until fresh requests refill it.
//
// In steady state this caps sustained retries at roughly `ratio` × request rate;
// `max` sets the initial burst allowance. It is lock-free: tokens are stored as
// float64 bits in an atomic and updated with a compare-and-swap loop.
type retryBudget struct {
	max    float64
	ratio  float64
	tokens atomic.Uint64 // math.Float64bits of the current token count
}

func newRetryBudget(maxTokens int, ratio float64) *retryBudget {
	if maxTokens <= 0 {
		maxTokens = 100
	}
	b := &retryBudget{max: float64(maxTokens), ratio: ratio}
	b.tokens.Store(math.Float64bits(b.max)) // start full so early traffic can retry
	return b
}

// deposit adds `ratio` tokens for a completed request, capped at max.
func (b *retryBudget) deposit() {
	for {
		oldBits := b.tokens.Load()
		cur := math.Float64frombits(oldBits)
		next := cur + b.ratio
		if next > b.max {
			next = b.max
		}
		if b.tokens.CompareAndSwap(oldBits, math.Float64bits(next)) {
			return
		}
	}
}

// withdraw takes one token for a retry. It returns true when a token was
// available (retry permitted) and false when the budget is exhausted.
func (b *retryBudget) withdraw() bool {
	for {
		oldBits := b.tokens.Load()
		cur := math.Float64frombits(oldBits)
		if cur < 1 {
			return false
		}
		if b.tokens.CompareAndSwap(oldBits, math.Float64bits(cur-1)) {
			return true
		}
	}
}

// available reports the current token count (used in tests).
func (b *retryBudget) available() float64 {
	return math.Float64frombits(b.tokens.Load())
}
