package proxy

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"algoryn.io/relay/internal/config"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func TestPassiveOutlierOutcomeIgnoresClientCancellation(t *testing.T) {
	if failure, count := passiveOutlierOutcome(0, context.Canceled); failure || count {
		t.Fatalf("client cancellation counted as outcome: failure=%v count=%v", failure, count)
	}
	if failure, count := passiveOutlierOutcome(0, errors.New("connection reset")); !failure || !count {
		t.Fatalf("network error not counted: failure=%v count=%v", failure, count)
	}
	if failure, count := passiveOutlierOutcome(503, nil); !failure || !count {
		t.Fatalf("5xx not counted: failure=%v count=%v", failure, count)
	}
	if failure, count := passiveOutlierOutcome(404, nil); failure || !count {
		t.Fatalf("non-5xx outcome incorrect: failure=%v count=%v", failure, count)
	}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func TestOutlierFailureRateWindowAndExponentialEjection(t *testing.T) {
	start := time.Unix(1_000, 0)
	clock := &fakeClock{now: start}
	state := newOutlierState(config.OutlierDetectionConfig{
		Window:               10 * time.Second,
		FailureRatePercent:   50,
		MinimumVolume:        4,
		BaseEjectionDuration: time.Second,
		MaxEjectionDuration:  2 * time.Second,
	})

	if reason := state.record(clock.Now(), true); reason != "" {
		t.Fatalf("early trigger = %q", reason)
	}
	state.record(clock.Now(), false)
	state.record(clock.Now(), true)
	if reason := state.record(clock.Now(), false); reason != "" {
		t.Fatalf("rate below threshold triggered %q", reason)
	}
	if reason := state.record(clock.Now(), true); reason != "failure_rate" {
		t.Fatalf("trigger = %q, want failure_rate", reason)
	}
	if until := state.eject(clock.Now(), "failure_rate"); !until.Equal(start.Add(time.Second)) {
		t.Fatalf("first ejection until = %v", until)
	}

	clock.Advance(time.Second)
	if ejected, recovered := state.ejectionStatus(clock.Now()); ejected || !recovered {
		t.Fatalf("expiry status = (%v, %v)", ejected, recovered)
	}
	for i := 0; i < 4; i++ {
		state.record(clock.Now(), true)
	}
	if until := state.eject(clock.Now(), "failure_rate"); !until.Equal(clock.Now().Add(2 * time.Second)) {
		t.Fatalf("second ejection did not use capped exponential duration: %v", until)
	}
}

func TestOutlierConcurrentEjectionHonorsBackendPercent(t *testing.T) {
	clock := &fakeClock{now: time.Unix(2_000, 0)}
	cfg := config.OutlierDetectionConfig{
		ConsecutiveFailures:  1,
		BaseEjectionDuration: time.Minute,
		MaxEjectionDuration:  time.Minute,
		MaxEjectionPercent:   50,
	}
	p := &Proxy{
		instances: map[string][]*instanceState{"api": {}},
		backends:  map[string]config.BackendRuntime{"api": {Name: "api"}},
		metrics:   nopMetrics{},
		clock:     clock,
	}
	for i := 0; i < 10; i++ {
		p.instances["api"] = append(p.instances["api"], &instanceState{
			Healthy: true,
			outlier: newOutlierState(cfg),
		})
	}

	var wg sync.WaitGroup
	for _, state := range p.instances["api"] {
		state := state
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				p.recordOutlierOutcome("api", state, true, false)
			}()
		}
	}
	wg.Wait()

	ejected := 0
	for _, state := range p.instances["api"] {
		active, _, _, _ := state.outlier.snapshot(clock.Now())
		if active {
			ejected++
		}
	}
	if ejected != 5 {
		t.Fatalf("ejected = %d, want 5", ejected)
	}
}
