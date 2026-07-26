package proxy

import (
	"errors"
	"fmt"
	"math/rand/v2"
)

// errAllCircuitsOpen is returned by selectInstance when every healthy instance
// has an open circuit breaker. Callers translate this to 503.
var errAllCircuitsOpen = errors.New("all instances have open circuits")

// errBulkheadFull is returned by resolveBackendChain when every candidate
// backend rejected the request due to its concurrency limit.
var errBulkheadFull = errors.New("bulkhead full")

func (p *Proxy) selectInstance(backendName, strategy string) (*instanceState, error) {
	// Read lock only: instance health is written under the write lock (health
	// loop / drain), while activeRequests and the round-robin counter are atomic.
	// This lets concurrent requests select instances without serializing.
	p.mu.RLock()

	states := p.instances[backendName]
	healthy := make([]*instanceState, 0, len(states))
	recovered := make([]*instanceState, 0, 1)
	circuitBlocked := 0
	now := p.clock.Now()
	for _, state := range states {
		if state != nil && state.Healthy && state.URL != nil {
			if ejected, didRecover := state.outlier.ejectionStatus(now); ejected {
				continue
			} else if didRecover {
				recovered = append(recovered, state)
			}
			if state.circuit != nil && state.circuit.IsOpen() {
				circuitBlocked++
			} else {
				healthy = append(healthy, state)
			}
		}
	}

	if len(healthy) == 0 {
		p.mu.RUnlock()
		for _, state := range recovered {
			p.emitOutlierRecovery(backendName, state, "duration_elapsed")
		}
		if circuitBlocked > 0 {
			return nil, errAllCircuitsOpen
		}
		return nil, fmt.Errorf("no healthy instances for backend %q", backendName)
	}

	var selected *instanceState
	switch strategy {
	case "least_connections":
		selected = healthy[0]
		for _, state := range healthy[1:] {
			if state.activeRequests.Load() < selected.activeRequests.Load() {
				selected = state
			}
		}

	case "weighted_random":
		total := 0
		for _, state := range healthy {
			total += state.weight
		}
		// #nosec G404 -- load-balancer selection does not require cryptographic randomness.
		pick := rand.IntN(total)
		acc := 0
		for _, state := range healthy {
			acc += state.weight
			if pick < acc {
				selected = state
				break
			}
		}
		if selected == nil {
			selected = healthy[len(healthy)-1]
		}

	default: // round_robin
		if c := p.roundRobin[backendName]; c != nil {
			idx := (c.Add(1) - 1) % uint64(len(healthy))
			selected = healthy[idx]
		} else {
			selected = healthy[0]
		}
	}

	selected.activeRequests.Add(1)
	p.mu.RUnlock()
	for _, state := range recovered {
		p.emitOutlierRecovery(backendName, state, "duration_elapsed")
	}
	return selected, nil
}
