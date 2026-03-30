package proxy

import (
	"fmt"
)

func (p *Proxy) selectInstance(backendName, strategy string) (*instanceState, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	states := p.instances[backendName]
	healthy := make([]*instanceState, 0, len(states))
	for _, state := range states {
		if state != nil && state.Healthy && state.URL != nil {
			healthy = append(healthy, state)
		}
	}

	if len(healthy) == 0 {
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
	default:
		idx := p.roundRobin[backendName] % len(healthy)
		selected = healthy[idx]
		p.roundRobin[backendName] = (p.roundRobin[backendName] + 1) % len(healthy)
	}

	selected.ActiveRequests++
	return selected, nil
}
