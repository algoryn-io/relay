package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	"algoryn.io/relay/internal/config"
	"algoryn.io/relay/internal/httpx"
)

type instanceState struct {
	URL            *url.URL
	Healthy        bool
	LastChecked    time.Time
	ActiveRequests int
	circuit        *CircuitBreaker // nil when circuit breaker is disabled
}

// HealthNotifier receives backend health state changes from the health check loop.
type HealthNotifier interface {
	NotifyBackendHealth(backend, instance string, healthy bool)
}

type Proxy struct {
	cancel         context.CancelFunc
	ctx            context.Context
	mu             sync.RWMutex
	logger         *slog.Logger
	healthNotifier HealthNotifier
	backends       map[string]config.BackendRuntime
	instances      map[string][]*instanceState
	roundRobin     map[string]int
}

func (p *Proxy) SetHealthNotifier(n HealthNotifier) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.healthNotifier = n
}

func New(rt *config.RuntimeConfig, logger *slog.Logger) (*Proxy, error) {
	if rt == nil {
		return nil, fmt.Errorf("runtime config is nil")
	}

	ctx, cancel := context.WithCancel(context.Background())

	p := &Proxy{
		cancel:     cancel,
		ctx:        ctx,
		logger:     logger,
		backends:   rt.Backends,
		instances:  make(map[string][]*instanceState, len(rt.Backends)),
		roundRobin: make(map[string]int, len(rt.Backends)),
	}

	for name, backend := range rt.Backends {
		// Start instances as unhealthy when health checks are configured so that
		// the first check (which runs immediately in healthLoop) determines state
		// before traffic is served. Without health checks, assume healthy.
		hasHealthCheck := backend.HealthCheck.Path != "" && backend.HealthCheck.Interval > 0

		var cbProto *CircuitBreaker
		if backend.CircuitBreaker.Threshold > 0 {
			cbProto = newCircuitBreaker(backend.CircuitBreaker.Threshold, backend.CircuitBreaker.Timeout)
		}

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
			var cb *CircuitBreaker
			if cbProto != nil {
				cb = newCircuitBreaker(cbProto.threshold, cbProto.timeout)
			}
			states = append(states, &instanceState{
				URL:         parsed,
				Healthy:     !hasHealthCheck,
				LastChecked: time.Now(),
				circuit:     cb,
			})
		}

		p.instances[name] = states
		p.roundRobin[name] = 0

		if hasHealthCheck {
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
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	backend, ok := p.backends[route.BackendName]
	if !ok {
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	selected, err := p.selectInstance(backend.Name, backend.Strategy)
	if err != nil {
		if errors.Is(err, errAllCircuitsOpen) {
			if p.logger != nil {
				p.logger.Warn("all instances have open circuits", "backend", backend.Name)
			}
			httpx.WriteError(w, http.StatusServiceUnavailable, "circuit_open")
		} else {
			httpx.WriteError(w, http.StatusBadGateway, "bad_gateway")
		}
		return
	}
	defer p.releaseInstance(backend.Name, selected)

	// Circuit breaker gate: IsOpen() is checked in selectInstance, but Allow()
	// handles the Open→HalfOpen transition and acts as the definitive gate.
	if selected.circuit != nil && !selected.circuit.Allow() {
		if p.logger != nil {
			p.logger.Warn("circuit open, request rejected",
				"backend", backend.Name,
				"instance", selected.URL.String(),
			)
		}
		httpx.WriteError(w, http.StatusServiceUnavailable, "circuit_open")
		return
	}

	target := selected.URL
	clientIP := httpx.ClientIP(r)

	// Preserve the forwarded scheme from an upstream TLS terminator when present.
	proto := r.Header.Get("X-Forwarded-Proto")
	if proto == "" {
		if r.TLS != nil {
			proto = "https"
		} else {
			proto = "http"
		}
	}
	originalHost := r.Host
	backendName := backend.Name

	var transport http.RoundTripper
	if selected.circuit != nil {
		transport = &circuitTransport{base: http.DefaultTransport, circuit: selected.circuit}
	}

	rp := &httputil.ReverseProxy{
		Transport: transport,
		// Use Rewrite (Go 1.22+) instead of Director so that the stdlib does not
		// append an extra X-Forwarded-For after our Rewrite func runs. The Rewrite
		// path strips X-Forwarded-*, Forwarded, etc. before calling us, giving us
		// full control over those headers.
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)

			// Strip client-injectable sensitive headers that are not covered by the
			// Rewrite path's automatic stripping.
			pr.Out.Header.Del("X-Internal-Auth")
			pr.Out.Header.Del("X-Real-IP")
			pr.Out.Header.Del("X-Admin")

			pr.Out.Header.Set("X-Forwarded-Host", originalHost)
			pr.Out.Header.Set("X-Forwarded-Proto", proto)
			if clientIP != "" {
				pr.Out.Header.Set("X-Forwarded-For", clientIP)
				pr.Out.Header.Set("X-Real-IP", clientIP)
			}
		},
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, err error) {
			if errors.Is(err, context.DeadlineExceeded) {
				if p.logger != nil {
					p.logger.Warn("backend timeout",
						"error", err,
						"path", req.URL.Path,
						"method", req.Method,
						"backend", backendName,
					)
				}
				httpx.WriteError(rw, http.StatusGatewayTimeout, "gateway_timeout")
				return
			}
			if p.logger != nil {
				p.logger.Error("backend connection error",
					"error", err,
					"path", req.URL.Path,
					"method", req.Method,
					"backend", backendName,
				)
			}
			httpx.WriteError(rw, http.StatusBadGateway, "bad_gateway")
		},
	}

	rp.ServeHTTP(w, r)
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
