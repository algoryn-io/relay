package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

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

	// Preserve values derived from the original request before any mutations.
	clientIP := httpx.ClientIP(r)
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

	retry := backend.Retry
	maxAttempts := retry.Attempts
	if maxAttempts <= 0 {
		maxAttempts = 1
	}

	// Buffer the request body so it can be replayed on retries.
	// If the body exceeds 1 MB or cannot be read, retry is disabled.
	var bodyBytes []byte
	bodyBuffered := false
	if maxAttempts > 1 && r.Body != nil && r.Body != http.NoBody {
		const maxBodyBuffer = 1 << 20 // 1 MB
		lr := &io.LimitedReader{R: r.Body, N: int64(maxBodyBuffer) + 1}
		data, err := io.ReadAll(lr)
		_ = r.Body.Close()
		if err != nil || lr.N == 0 {
			// Body unreadable or too large: disable retry, restore what we read.
			maxAttempts = 1
			if err == nil {
				r.Body = io.NopCloser(bytes.NewReader(data))
			}
		} else {
			bodyBytes = data
			bodyBuffered = true
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
	}

	var lastBuf *responseBuffer

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if bodyBuffered && attempt > 0 {
			r = r.Clone(r.Context())
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}

		selected, selErr := p.selectInstance(backend.Name, backend.Strategy)
		if selErr != nil {
			if errors.Is(selErr, errAllCircuitsOpen) {
				if p.logger != nil {
					p.logger.Warn("all instances have open circuits", "backend", backend.Name)
				}
				httpx.WriteError(w, http.StatusServiceUnavailable, "circuit_open")
			} else {
				httpx.WriteError(w, http.StatusBadGateway, "bad_gateway")
			}
			return
		}

		// Circuit breaker gate: Allow() handles the Open→HalfOpen transition.
		if selected.circuit != nil && !selected.circuit.Allow() {
			p.releaseInstance(backend.Name, selected)
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
		var transport http.RoundTripper
		if selected.circuit != nil {
			transport = &circuitTransport{base: http.DefaultTransport, circuit: selected.circuit}
		}

		buf := newResponseBuffer()

		rp := &httputil.ReverseProxy{
			Transport: transport,
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.SetURL(target)
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
				buf.networkErr = err
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

		rp.ServeHTTP(buf, r)
		p.releaseInstance(backend.Name, selected)
		lastBuf = buf

		isNetErr := buf.networkErr != nil
		if !shouldRetry(buf.Status(), isNetErr, retry, r.Method) || attempt == maxAttempts-1 {
			break
		}

		// Record the retry on the active OTel span so it appears in traces.
		reason := "5xx"
		if isNetErr {
			reason = "network_error"
		}
		trace.SpanFromContext(r.Context()).AddEvent("proxy.retry",
			trace.WithAttributes(
				attribute.Int("retry.attempt", attempt+1),
				attribute.String("retry.reason", reason),
				attribute.String("relay.backend", backendName),
			),
		)

		if p.logger != nil {
			p.logger.Warn("retrying request",
				"backend", backendName,
				"attempt", attempt+1,
				"reason", reason,
			)
		}

		select {
		case <-r.Context().Done():
			httpx.WriteError(w, http.StatusServiceUnavailable, "context_canceled")
			return
		case <-time.After(computeBackoff(attempt, retry)):
		}
	}

	lastBuf.flushTo(w)
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
