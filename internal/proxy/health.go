package proxy

import (
	"net/http"
	"net/url"
	"time"

	"algoryn.io/relay/internal/config"
)

func (p *Proxy) healthLoop(backendName string, health config.HealthCheckConfig) {
	p.checkBackendHealth(backendName, health)

	ticker := time.NewTicker(health.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.checkBackendHealth(backendName, health)
		}
	}
}

func (p *Proxy) checkBackendHealth(backendName string, health config.HealthCheckConfig) {
	client := &http.Client{Timeout: health.Timeout}

	p.mu.RLock()
	states := append([]*instanceState(nil), p.instances[backendName]...)
	p.mu.RUnlock()

	for _, state := range states {
		if state == nil || state.URL == nil {
			p.updateInstanceHealth(backendName, state, false)
			continue
		}

		target := state.URL.ResolveReference(&url.URL{Path: health.Path})
		req, err := http.NewRequest(http.MethodGet, target.String(), nil)
		if err != nil {
			p.updateInstanceHealth(backendName, state, false)
			continue
		}

		resp, err := client.Do(req)
		healthy := err == nil && resp.StatusCode >= 200 && resp.StatusCode < 300
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}

		p.updateInstanceHealth(backendName, state, healthy)
	}
}

func (p *Proxy) updateInstanceHealth(backendName string, target *instanceState, healthy bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, state := range p.instances[backendName] {
		if state == target {
			state.Healthy = healthy
			state.LastChecked = time.Now()
			return
		}
	}
}
