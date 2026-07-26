package proxy

import (
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"algoryn.io/relay/internal/config"
	"algoryn.io/relay/internal/discovery"
)

func (p *Proxy) startDiscovery(backendName string, dns *config.DNSDiscoveryConfig) {
	if dns == nil {
		return
	}
	p.discoveryWG.Add(1)
	go p.discoveryLoop(backendName, dns)
}

func (p *Proxy) discoveryLoop(backendName string, dns *config.DNSDiscoveryConfig) {
	defer p.discoveryWG.Done()

	for {
		ttl := p.nextDiscoveryInterval(backendName, dns)
		timer := time.NewTimer(ttl)
		select {
		case <-p.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			p.refreshDiscoveredBackend(backendName, dns)
		}
	}
}

func (p *Proxy) nextDiscoveryInterval(backendName string, dns *config.DNSDiscoveryConfig) time.Duration {
	p.mu.RLock()
	ttl := p.discoveryTTL[backendName]
	p.mu.RUnlock()
	return discovery.ClampTTL(ttl, dns.RefreshInterval, dns.TTLMin, dns.TTLMax)
}

func (p *Proxy) refreshDiscoveredBackend(backendName string, dns *config.DNSDiscoveryConfig) {
	recordType := strings.ToUpper(strings.TrimSpace(dns.RecordType))
	if recordType == "" {
		recordType = discovery.RecordTypeA
	}
	res, err := p.resolver.Resolve(p.ctx, discovery.Query{
		Name:       dns.Name,
		RecordType: recordType,
	})
	if err != nil {
		if p.ctx.Err() != nil {
			return
		}
		if p.logger != nil {
			p.logger.Warn("dns discovery refresh failed",
				"backend", backendName,
				"name", dns.Name,
				"record_type", recordType,
				"error", err,
			)
		}
		return
	}

	endpoints := materializeEndpoints(res.Endpoints, dns)
	p.applyDiscoveredInstances(backendName, endpoints, res.TTL)
}

func materializeEndpoints(endpoints []discovery.Endpoint, dns *config.DNSDiscoveryConfig) []discovery.Endpoint {
	scheme := strings.ToLower(strings.TrimSpace(dns.Scheme))
	if scheme == "" {
		scheme = "http"
	}
	recordType := strings.ToUpper(strings.TrimSpace(dns.RecordType))
	if recordType == "" {
		recordType = discovery.RecordTypeA
	}
	defaultWeight := dns.Weight
	if defaultWeight <= 0 {
		defaultWeight = 1
	}

	out := make([]discovery.Endpoint, 0, len(endpoints))
	seen := make(map[string]struct{}, len(endpoints))
	for _, ep := range endpoints {
		host := strings.TrimSpace(ep.Host)
		if host == "" {
			continue
		}
		port := ep.Port
		if recordType == discovery.RecordTypeA || recordType == discovery.RecordTypeAAAA {
			port = dns.Port
		}
		if port <= 0 || port > 65535 {
			continue
		}
		weight := ep.Weight
		if weight <= 0 {
			weight = defaultWeight
		}
		key := endpointURL(scheme, host, port)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, discovery.Endpoint{Host: host, Port: port, Weight: weight})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].Port < out[j].Port
	})
	return out
}

func endpointURL(scheme, host string, port int) string {
	return (&url.URL{
		Scheme: scheme,
		Host:   net.JoinHostPort(host, fmt.Sprintf("%d", port)),
	}).String()
}

// applyDiscoveredInstances atomically replaces the backend instance pool.
// Existing instance state (health, circuit, outlier, in-flight) is preserved for
// URLs that remain in the new set.
func (p *Proxy) applyDiscoveredInstances(backendName string, endpoints []discovery.Endpoint, ttl time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()

	backend, ok := p.backends[backendName]
	if !ok || backend.Discovery == nil {
		return
	}
	scheme := strings.ToLower(strings.TrimSpace(backend.Discovery.Scheme))
	if scheme == "" {
		scheme = "http"
	}

	hasHealthCheck := backend.HealthCheck.Path != "" && backend.HealthCheck.Interval > 0
	oldByURL := make(map[string]*instanceState, len(p.instances[backendName]))
	for _, state := range p.instances[backendName] {
		if state != nil && state.URL != nil {
			oldByURL[state.URL.String()] = state
		}
	}

	var cbProto *CircuitBreaker
	if backend.CircuitBreaker.Threshold > 0 {
		cbProto = newCircuitBreaker(backend.CircuitBreaker.Threshold, backend.CircuitBreaker.Timeout)
	}

	states := make([]*instanceState, 0, len(endpoints))
	for _, ep := range endpoints {
		rawURL := endpointURL(scheme, ep.Host, ep.Port)
		if existing, ok := oldByURL[rawURL]; ok {
			if ep.Weight > 0 {
				existing.weight = ep.Weight
			}
			states = append(states, existing)
			continue
		}
		parsed, err := url.Parse(rawURL)
		if err != nil {
			continue
		}
		var cb *CircuitBreaker
		if cbProto != nil {
			cb = newCircuitBreaker(cbProto.threshold, cbProto.timeout)
		}
		weight := ep.Weight
		if weight <= 0 {
			weight = 1
		}
		states = append(states, &instanceState{
			URL:         parsed,
			Healthy:     !hasHealthCheck,
			LastChecked: p.clock.Now(),
			weight:      weight,
			circuit:     cb,
			outlier:     newInstanceOutlier(backend.OutlierDetection),
		})
	}

	p.instances[backendName] = states
	p.discoveryTTL[backendName] = ttl
	if p.roundRobin[backendName] == nil {
		p.roundRobin[backendName] = new(atomic.Uint64)
	}
}

// resolveBackendChain tries preferred, then ordered failover backends.
func (p *Proxy) resolveBackendChain(routeName, preferred string, failover []string) (config.BackendRuntime, func(), error) {
	candidates := make([]string, 0, 1+len(failover))
	candidates = append(candidates, preferred)
	for _, name := range failover {
		if name == preferred {
			continue
		}
		candidates = append(candidates, name)
	}

	var firstErr error
	for _, name := range candidates {
		backend, ok := p.backends[name]
		if !ok {
			continue
		}
		if !p.backendHasSelectableInstance(name) {
			if firstErr == nil {
				if p.backendAllCircuitsOpen(name) {
					firstErr = errAllCircuitsOpen
				} else {
					firstErr = fmt.Errorf("no healthy instances for backend %q", name)
				}
			}
			continue
		}

		bh := p.bulkheads[name]
		if bh != nil {
			if !bh.Acquire() {
				p.metricsSink().RecordBulkheadRejected(name)
				if firstErr == nil {
					firstErr = errBulkheadFull
				}
				continue
			}
			p.metricsSink().SetBulkheadInFlight(name, bh.InFlight())
			release := func() {
				bh.Release()
				p.metricsSink().SetBulkheadInFlight(name, bh.InFlight())
			}
			return backend, release, nil
		}
		return backend, func() {}, nil
	}

	if firstErr == nil {
		firstErr = fmt.Errorf("no backends available for route %q", routeName)
	}
	return config.BackendRuntime{}, func() {}, firstErr
}

func (p *Proxy) backendHasSelectableInstance(backendName string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	now := p.clock.Now()
	for _, state := range p.instances[backendName] {
		if state == nil || state.URL == nil || !state.Healthy {
			continue
		}
		if ejected, _ := state.outlier.ejectionStatus(now); ejected {
			continue
		}
		if state.circuit != nil && state.circuit.IsOpen() {
			continue
		}
		return true
	}
	return false
}

func (p *Proxy) backendAllCircuitsOpen(backendName string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	states := p.instances[backendName]
	if len(states) == 0 {
		return false
	}
	healthy := 0
	blocked := 0
	now := p.clock.Now()
	for _, state := range states {
		if state == nil || state.URL == nil || !state.Healthy {
			continue
		}
		if ejected, _ := state.outlier.ejectionStatus(now); ejected {
			continue
		}
		healthy++
		if state.circuit != nil && state.circuit.IsOpen() {
			blocked++
		}
	}
	return healthy > 0 && blocked == healthy
}
