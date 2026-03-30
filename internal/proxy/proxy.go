package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	"algoryn.io/relay/internal/config"
)

type instanceState struct {
	URL            *url.URL
	Healthy        bool
	LastChecked    time.Time
	ActiveRequests int
}

type Proxy struct {
	cancel     context.CancelFunc
	ctx        context.Context
	mu         sync.RWMutex
	backends   map[string]config.BackendRuntime
	instances  map[string][]*instanceState
	roundRobin map[string]int
}

func New(rt *config.RuntimeConfig) (*Proxy, error) {
	if rt == nil {
		return nil, fmt.Errorf("runtime config is nil")
	}

	ctx, cancel := context.WithCancel(context.Background())

	p := &Proxy{
		cancel:     cancel,
		ctx:        ctx,
		backends:   rt.Backends,
		instances:  make(map[string][]*instanceState, len(rt.Backends)),
		roundRobin: make(map[string]int, len(rt.Backends)),
	}

	for name, backend := range rt.Backends {
		states := make([]*instanceState, 0, len(backend.Instances))
		for _, instance := range backend.Instances {
			parsed, err := url.Parse(instance.URL)
			if err != nil {
				states = append(states, &instanceState{
					Healthy:     false,
					LastChecked: time.Now(),
				})
				continue
			}

			states = append(states, &instanceState{
				URL:         parsed,
				Healthy:     true,
				LastChecked: time.Now(),
			})
		}

		p.instances[name] = states
		p.roundRobin[name] = 0

		if backend.HealthCheck.Path != "" && backend.HealthCheck.Interval > 0 {
			go p.healthLoop(name, backend.HealthCheck)
		}
	}

	return p, nil
}

func (p *Proxy) Close() {
	if p != nil && p.cancel != nil {
		p.cancel()
	}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request, route *config.RouteRuntime) {
	if p == nil || route == nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	backend, ok := p.backends[route.BackendName]
	if !ok {
		writeJSONError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	selected, err := p.selectInstance(backend.Name, backend.Strategy)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, "bad_gateway")
		return
	}
	defer p.releaseInstance(backend.Name, selected)

	proxy := httputil.NewSingleHostReverseProxy(selected.URL)
	director := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalHost := req.Host
		proto := "http"
		if req.TLS != nil {
			proto = "https"
		}

		director(req)
		setForwardedHeaders(req, originalHost, proto)
	}
	proxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
		writeJSONError(rw, http.StatusBadGateway, "bad_gateway")
	}

	proxy.ServeHTTP(w, r)
}

func setForwardedHeaders(req *http.Request, originalHost, proto string) {
	req.Header.Set("X-Forwarded-Host", originalHost)
	req.Header.Set("X-Forwarded-Proto", proto)
}

func (p *Proxy) releaseInstance(backendName string, selected *instanceState) {
	if selected == nil {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	for _, state := range p.instances[backendName] {
		if state == selected && state.ActiveRequests > 0 {
			state.ActiveRequests--
			return
		}
	}
}

func writeJSONError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":  code,
		"status": "error",
	})
}
