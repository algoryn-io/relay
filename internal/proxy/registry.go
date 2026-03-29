package proxy

import (
	"sync"

	"algoryn.io/relay/internal/config"
)

type Instance struct {
	URL         string
	Healthy     bool
	ActiveConns int64
}

type BackendRegistry interface {
	List(name string) []*Instance
	Register(name string, instance *Instance)
	SetHealthy(name string, url string, healthy bool)
}

type ConfigRegistry struct {
	mu       sync.RWMutex
	backends map[string][]*Instance
}

var _ BackendRegistry = (*ConfigRegistry)(nil)

func NewConfigRegistry(backends []config.BackendConfig) *ConfigRegistry {
	r := &ConfigRegistry{
		backends: make(map[string][]*Instance, len(backends)),
	}
	for _, backend := range backends {
		instances := make([]*Instance, 0, len(backend.Instances))
		for _, inst := range backend.Instances {
			instances = append(instances, &Instance{
				URL:     inst.URL,
				Healthy: true,
			})
		}
		r.backends[backend.Name] = instances
	}
	return r
}

func (r *ConfigRegistry) List(name string) []*Instance {
	r.mu.RLock()
	defer r.mu.RUnlock()

	instances := r.backends[name]
	out := make([]*Instance, len(instances))
	copy(out, instances)
	return out
}

func (r *ConfigRegistry) Register(name string, instance *Instance) {
	if instance == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.backends[name] = append(r.backends[name], instance)
}

func (r *ConfigRegistry) SetHealthy(name string, url string, healthy bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, instance := range r.backends[name] {
		if instance.URL == url {
			instance.Healthy = healthy
			return
		}
	}
}
