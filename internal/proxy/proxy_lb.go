package proxy

import (
	"errors"
	"fmt"
	"math/rand/v2"
)

// errAllCircuitsOpen is returned by selectInstance when every healthy instance
// has an open circuit breaker. Callers translate this to 503.
var errAllCircuitsOpen = errors.New("all instances have open circuits")

func (p *Proxy) selectInstance(backendName, strategy string) (*instanceState, error) {
	// Read lock only: instance health is written under the write lock (health
	// loop / drain), while activeRequests and the round-robin counter are atomic.
	// This lets concurrent requests select instances without serializing.
	p.mu.RLock()
	defer p.mu.RUnlock()

	states := p.instances[backendName]
	healthy := make([]*instanceState, 0, len(states))
	circuitBlocked := 0
	for _, state := range states {
		if state != nil && state.Healthy && state.URL != nil {
			if state.circuit != nil && state.circuit.IsOpen() {
				circuitBlocked++
			} else {
				healthy = append(healthy, state)
			}
		}
	}

	if len(healthy) == 0 {
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
			idx := int((c.Add(1) - 1) % uint64(len(healthy)))
			selected = healthy[idx]
		} else {
			selected = healthy[0]
		}
	}

	selected.activeRequests.Add(1)
	return selected, nil
}
