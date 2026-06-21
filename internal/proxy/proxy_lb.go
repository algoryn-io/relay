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
	p.mu.Lock()
	defer p.mu.Unlock()

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
			if state.ActiveRequests < selected.ActiveRequests {
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
		idx := p.roundRobin[backendName] % len(healthy)
		selected = healthy[idx]
		p.roundRobin[backendName] = (p.roundRobin[backendName] + 1) % len(healthy)
	}

	selected.ActiveRequests++
	return selected, nil
}
