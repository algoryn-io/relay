package proxy

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"algoryn.io/relay/internal/config"
)

func TestRetryBudgetWithdrawUntilEmpty(t *testing.T) {
	t.Parallel()

	b := newRetryBudget(3, 0) // 3 tokens, no replenishment
	for i := 0; i < 3; i++ {
		if !b.withdraw() {
			t.Fatalf("withdraw %d should succeed", i)
		}
	}
	if b.withdraw() {
		t.Fatal("withdraw should fail once the budget is empty")
	}
}

func TestRetryBudgetDepositCapsAtMax(t *testing.T) {
	t.Parallel()

	b := newRetryBudget(2, 0.5)
	// Starts full at max=2. Depositing must not exceed max.
	b.deposit()
	b.deposit()
	if got := b.available(); got != 2 {
		t.Fatalf("available = %v, want 2 (capped)", got)
	}
	// Withdraw one, deposit 0.5 back.
	b.withdraw()
	b.deposit()
	if got := b.available(); got != 1.5 {
		t.Fatalf("available = %v, want 1.5", got)
	}
}

// budgetMetrics is a minimal ProxyMetrics that counts budget-exhausted events.
type budgetMetrics struct {
	nopMetrics
	exhausted atomic.Int64
	retries   atomic.Int64
}

func (m *budgetMetrics) RecordRetry(string, string)        { m.retries.Add(1) }
func (m *budgetMetrics) RecordRetryBudgetExhausted(string) { m.exhausted.Add(1) }

func TestProxyRetryBudgetSuppressesRetriesUnderSustainedFailure(t *testing.T) {
	t.Parallel()

	var backendHits atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendHits.Add(1)
		w.WriteHeader(http.StatusInternalServerError) // always fails → always retry-eligible
	}))
	defer backend.Close()

	p := newTestProxy(t, map[string]config.BackendRuntime{
		"failing": {
			Name:     "failing",
			Strategy: "round_robin",
			Retry: config.RetryConfig{
				Attempts:     2,
				On:           []string{"5xx"},
				BackoffInit:  time.Millisecond,
				BackoffMax:   time.Millisecond,
				BudgetRatio:  0.0001, // effectively no replenishment
				BudgetTokens: 1,      // exactly one retry allowed before exhaustion
			},
			Instances: []config.InstanceRuntime{{URL: backend.URL}},
		},
	})
	metrics := &budgetMetrics{}
	p.SetMetrics(metrics)

	const requests = 5
	for i := 0; i < requests; i++ {
		resp := performProxyRequest(t, p, &config.RouteRuntime{BackendName: "failing"}, http.MethodGet, "/x")
		resp.Body.Close()
	}

	// Without a budget, 5 requests × 2 attempts = 10 backend hits. The budget
	// allows only the first retry, so the rest are suppressed: the first request
	// makes 2 hits, the remaining 4 make 1 each = 6.
	if got := backendHits.Load(); got != 6 {
		t.Fatalf("backend hits = %d, want 6 (retry budget should suppress most retries)", got)
	}
	if metrics.retries.Load() != 1 {
		t.Fatalf("retries recorded = %d, want 1", metrics.retries.Load())
	}
	if metrics.exhausted.Load() != int64(requests-1) {
		t.Fatalf("budget-exhausted events = %d, want %d", metrics.exhausted.Load(), requests-1)
	}
}
