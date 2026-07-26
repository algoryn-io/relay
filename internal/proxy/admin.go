package proxy

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"algoryn.io/relay/internal/config"
)

// InstanceSnapshot is a point-in-time view of a single backend instance.
type InstanceSnapshot struct {
	URL            string `json:"url"`
	Healthy        bool   `json:"healthy"`
	ActiveRequests int    `json:"active_requests"`
	// CircuitState is the circuit breaker state ("closed", "open", "half_open").
	// Empty string when no circuit breaker is configured.
	CircuitState  string    `json:"circuit_state,omitempty"`
	Ejected       bool      `json:"ejected"`
	EjectedUntil  time.Time `json:"ejected_until,omitempty"`
	EjectReason   string    `json:"eject_reason,omitempty"`
	EjectionCount int       `json:"ejection_count,omitempty"`
}

// BackendSnapshot is a point-in-time view of a backend and its instances.
type BackendSnapshot struct {
	Name      string             `json:"name"`
	Strategy  string             `json:"strategy"`
	Instances []InstanceSnapshot `json:"instances"`
}

// BackendSnapshots returns a consistent read-only snapshot of all backends.
func (p *Proxy) BackendSnapshots() []BackendSnapshot {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result := make([]BackendSnapshot, 0, len(p.backends))
	for name, backend := range p.backends {
		insts := p.instances[name]
		snaps := make([]InstanceSnapshot, 0, len(insts))
		for _, inst := range insts {
			s := InstanceSnapshot{
				Healthy:        inst.Healthy,
				ActiveRequests: int(inst.activeRequests.Load()),
			}
			if inst.URL != nil {
				s.URL = inst.URL.String()
			}
			if inst.circuit != nil {
				s.CircuitState = inst.circuit.State()
			}
			s.Ejected, s.EjectedUntil, s.EjectReason, s.EjectionCount = inst.outlier.snapshot(p.clock.Now())
			snaps = append(snaps, s)
		}
		result = append(result, BackendSnapshot{
			Name:      name,
			Strategy:  backend.Strategy,
			Instances: snaps,
		})
	}
	return result
}

// BackendSnapshot returns the snapshot for a single named backend.
// Returns false as the second value when the backend does not exist.
func (p *Proxy) BackendSnapshot(name string) (BackendSnapshot, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	backend, ok := p.backends[name]
	if !ok {
		return BackendSnapshot{}, false
	}
	insts := p.instances[name]
	snaps := make([]InstanceSnapshot, 0, len(insts))
	for _, inst := range insts {
		s := InstanceSnapshot{
			Healthy:        inst.Healthy,
			ActiveRequests: int(inst.activeRequests.Load()),
		}
		if inst.URL != nil {
			s.URL = inst.URL.String()
		}
		if inst.circuit != nil {
			s.CircuitState = inst.circuit.State()
		}
		s.Ejected, s.EjectedUntil, s.EjectReason, s.EjectionCount = inst.outlier.snapshot(p.clock.Now())
		snaps = append(snaps, s)
	}
	return BackendSnapshot{
		Name:      name,
		Strategy:  backend.Strategy,
		Instances: snaps,
	}, true
}

// Readiness reports aggregate backend health for the readiness probe.
// total is the number of configured backends; healthy is the number of backends
// that have at least one healthy instance. The gateway is considered ready when
// it has no backends, or when at least one backend can still serve traffic.
func (p *Proxy) Readiness() (healthy, total int) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for name := range p.backends {
		total++
		for _, inst := range p.instances[name] {
			ejected, _, _, _ := inst.outlier.snapshot(p.clock.Now())
			if inst.Healthy && !ejected {
				healthy++
				break
			}
		}
	}
	return healthy, total
}

// ReadinessEvaluation is the diagnostic form of readiness. It is intended only
// for an authenticated admin endpoint; public readiness responses must not
// serialize this value.
type ReadinessEvaluation struct {
	Ready    bool                     `json:"ready"`
	Mode     string                   `json:"mode"`
	Serving  int                      `json:"serving_backends"`
	Total    int                      `json:"total_backends"`
	Backends []ReadinessBackendStatus `json:"backends"`
}

type ReadinessBackendStatus struct {
	Name      string             `json:"name"`
	Required  bool               `json:"required"`
	Serving   bool               `json:"serving"`
	Reason    string             `json:"reason"`
	Instances []InstanceSnapshot `json:"instances"`
}

// EvaluateReadiness evaluates any/all/critical backend policy and returns
// diagnostic detail suitable for the admin API.
func (p *Proxy) EvaluateReadiness(policy config.ReadinessPolicyConfig) ReadinessEvaluation {
	p.mu.RLock()
	defer p.mu.RUnlock()

	mode := strings.ToLower(strings.TrimSpace(policy.Mode))
	if mode == "" {
		mode = "any"
	}
	critical := make(map[string]struct{}, len(policy.CriticalBackends))
	for _, name := range policy.CriticalBackends {
		critical[strings.TrimSpace(name)] = struct{}{}
	}

	names := make([]string, 0, len(p.backends))
	for name := range p.backends {
		names = append(names, name)
	}
	sort.Strings(names)

	result := ReadinessEvaluation{Mode: mode, Total: len(names)}
	requiredSeen := 0
	for _, name := range names {
		required := mode == "all"
		if mode == "critical" {
			_, required = critical[name]
			if required {
				requiredSeen++
			}
		}
		status := ReadinessBackendStatus{Name: name, Required: required}
		for _, inst := range p.instances[name] {
			snapshot := InstanceSnapshot{
				Healthy:        inst.Healthy,
				ActiveRequests: int(inst.activeRequests.Load()),
			}
			if inst.URL != nil {
				snapshot.URL = inst.URL.String()
			}
			if inst.circuit != nil {
				snapshot.CircuitState = inst.circuit.State()
			}
			snapshot.Ejected, snapshot.EjectedUntil, snapshot.EjectReason, snapshot.EjectionCount = inst.outlier.snapshot(p.clock.Now())
			status.Instances = append(status.Instances, snapshot)
			if snapshot.Healthy && !snapshot.Ejected {
				status.Serving = true
			}
		}
		if status.Serving {
			status.Reason = "ready"
			result.Serving++
		} else {
			status.Reason = "no_healthy_instance"
		}
		result.Backends = append(result.Backends, status)
	}

	switch mode {
	case "all":
		result.Ready = result.Serving == result.Total
	case "critical":
		result.Ready = len(critical) > 0 && requiredSeen == len(critical)
		for _, backend := range result.Backends {
			if backend.Required && !backend.Serving {
				result.Ready = false
			}
		}
	default:
		result.Ready = result.Total == 0 || result.Serving > 0
	}
	return result
}

// DrainInstance marks the given instance as unhealthy, removing it from the
// load-balancing pool until a health check restores it or the config is reloaded.
func (p *Proxy) DrainInstance(backendName, instanceURL string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	insts, ok := p.instances[backendName]
	if !ok {
		return fmt.Errorf("backend %q not found", backendName)
	}
	for _, inst := range insts {
		if inst.URL != nil && inst.URL.String() == instanceURL {
			inst.Healthy = false
			return nil
		}
	}
	return fmt.Errorf("instance %q not found in backend %q", instanceURL, backendName)
}

// ResetCircuit manually closes the circuit breaker for the given instance,
// allowing traffic to resume immediately.
func (p *Proxy) ResetCircuit(backendName, instanceURL string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	insts, ok := p.instances[backendName]
	if !ok {
		return fmt.Errorf("backend %q not found", backendName)
	}
	for _, inst := range insts {
		if inst.URL != nil && inst.URL.String() == instanceURL {
			if inst.circuit == nil {
				return fmt.Errorf("no circuit breaker configured for instance %q in backend %q", instanceURL, backendName)
			}
			inst.circuit.RecordSuccess()
			return nil
		}
	}
	return fmt.Errorf("instance %q not found in backend %q", instanceURL, backendName)
}
