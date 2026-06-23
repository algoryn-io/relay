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
	"strings"
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
	weight         int             // effective weight >= 1
	circuit        *CircuitBreaker // nil when circuit breaker is disabled
}

// HealthNotifier receives backend health state changes from the health check loop.
type HealthNotifier interface {
	NotifyBackendHealth(backend, instance string, healthy bool)
}

type Proxy struct {
	cancel            context.CancelFunc
	ctx               context.Context
	mu                sync.RWMutex
	logger            *slog.Logger
	healthNotifier    HealthNotifier
	backends          map[string]config.BackendRuntime
	instances         map[string][]*instanceState
	roundRobin        map[string]int
	backendTransports map[string]http.RoundTripper
	bulkheads         map[string]*bulkhead
}

func (p *Proxy) SetHealthNotifier(n HealthNotifier) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.healthNotifier = n
}

// SetWebSocketIdleTimeout configures the idle timeout applied to proxied
// WebSocket/upgrade tunnels. Must be called before serving traffic.
func (p *Proxy) SetWebSocketIdleTimeout(d time.Duration) {
	p.wsIdleTimeout = d
}

// SetMetrics wires the resilience metrics sink. Must be called before serving.
func (p *Proxy) SetMetrics(m ProxyMetrics) {
	if m == nil {
		m = nopMetrics{}
	}
	p.metrics = m
}

func New(rt *config.RuntimeConfig, logger *slog.Logger) (*Proxy, error) {
	if rt == nil {
		return nil, fmt.Errorf("runtime config is nil")
	}

	ctx, cancel := context.WithCancel(context.Background())

	p := &Proxy{
		cancel:            cancel,
		ctx:               ctx,
		logger:            logger,
		backends:          rt.Backends,
		instances:         make(map[string][]*instanceState, len(rt.Backends)),
		roundRobin:        make(map[string]int, len(rt.Backends)),
		backendTransports: make(map[string]http.RoundTripper, len(rt.Backends)),
		bulkheads:         make(map[string]*bulkhead, len(rt.Backends)),
	}

	for name, backend := range rt.Backends {
		if backend.Bulkhead.MaxConcurrent > 0 {
			p.bulkheads[name] = newBulkhead(backend.Bulkhead.MaxConcurrent)
		}

		// Every backend gets its own tuned transport (with TLS applied when
		// configured) so connection pooling is never left to http.DefaultTransport.
		tr, trErr := buildBackendTransport(backend.TLS)
		if trErr != nil {
			cancel()
			return nil, fmt.Errorf("backend %q: build transport: %w", name, trErr)
		}
		p.backendTransports[name] = tr
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
			w := instance.Weight
			if w <= 0 {
				w = 1
			}
			states = append(states, &instanceState{
				URL:         parsed,
				Healthy:     !hasHealthCheck,
				LastChecked: time.Now(),
				weight:      w,
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

	// Bulkhead: limit concurrent in-flight requests per backend.
	if bh := p.bulkheads[backendName]; bh != nil {
		if !bh.Acquire() {
			if p.logger != nil {
				p.logger.Warn("bulkhead full, request rejected",
					"backend", backendName,
					"limit", bh.Limit(),
					"in_flight", bh.InFlight(),
				)
			}
			httpx.WriteError(w, http.StatusServiceUnavailable, "bulkhead_full")
			return
		}
		defer bh.Release()
	}

	// WebSocket (and other protocol upgrades) bypass the retry loop and
	// responseBuffer: the real ResponseWriter must remain accessible for
	// http.Hijacker, and replaying a half-established connection is not possible.
	if isWebSocketUpgrade(r) {
		p.serveWebSocket(w, r, backend, clientIP, proto, originalHost)
		return
	}

	// Route-level body size limit. Validated and buffered here so the retry
	// loop can replay the body without re-reading from the (now-closed) socket.
	// When no limit is configured this block is skipped entirely.
	var bodyBytes []byte
	bodyBuffered := false
	if route.MaxBodyBytes > 0 && r.Body != nil && r.Body != http.NoBody {
		limited := &io.LimitedReader{R: r.Body, N: route.MaxBodyBytes + 1}
		data, readErr := io.ReadAll(limited)
		_ = r.Body.Close()
		if readErr != nil {
			httpx.WriteError(w, http.StatusBadRequest, "request_read_error")
			return
		}
		if limited.N == 0 {
			httpx.WriteError(w, http.StatusRequestEntityTooLarge, "request_body_too_large")
			return
		}
		bodyBytes = data
		bodyBuffered = true
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	retry := backend.Retry
	maxAttempts := retry.Attempts
	if maxAttempts <= 0 {
		maxAttempts = 1
	}

	// A request is retry-eligible only when more than one attempt is configured,
	// at least one retry condition is set, and the method is safe (or unsafe
	// methods are explicitly allowed). When it is not eligible there is no reason
	// to buffer: the response streams straight to the client. This keeps the hot
	// path allocation-free and preserves streaming/SSE for the common case.
	retryEligible := maxAttempts > 1 &&
		len(retry.On) > 0 &&
		(retry.AllowUnsafe || isSafeMethod(r.Method))
	if !retryEligible {
		maxAttempts = 1
	}

	// Buffer the request body for retry replay when no size limit was applied
	// above. A 1 MB cap prevents excessive memory use; bodies larger than that
	// disable retry (the single attempt still completes normally).
	if !bodyBuffered && retryEligible && r.Body != nil && r.Body != http.NoBody {
		const maxBodyBuffer = 1 << 20 // 1 MB
		lr := &io.LimitedReader{R: r.Body, N: int64(maxBodyBuffer) + 1}
		data, err := io.ReadAll(lr)
		_ = r.Body.Close()
		if err != nil || lr.N == 0 {
			// Body unreadable or too large: disable retry, restore what we read.
			maxAttempts = 1
			retryEligible = false
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
		transport := p.transportFor(backendName, selected.circuit)

		// When the request is retry-eligible, capture the response in a bounded
		// buffer so the status can be inspected before bytes reach the client.
		// Otherwise stream straight to the real ResponseWriter: no buffering, so
		// large responses and SSE/streaming work and memory stays flat.
		var dst http.ResponseWriter = w
		var buf *responseBuffer
		if retryEligible {
			buf = newResponseBuffer(w, maxRetryResponseBuffer)
			dst = buf
		}
		var netErr error

		rp := &httputil.ReverseProxy{
			Transport: transport,
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.SetURL(target)

				// Regex path rewriting — applied after SetURL so the backend
				// host is already set and we only modify the path segment.
				if route.Rewrite != nil {
					rewritten := route.Rewrite.Apply(pr.Out.URL.Path)
					if rewritten != pr.Out.URL.Path {
						pr.Out.URL.Path = rewritten
						pr.Out.URL.RawPath = ""
					}
				}

				pr.Out.Header.Del("X-Internal-Auth")
				pr.Out.Header.Del("X-Real-IP")
				pr.Out.Header.Del("X-Admin")
				pr.Out.Header.Set("X-Forwarded-Host", originalHost)
				pr.Out.Header.Set("X-Forwarded-Proto", proto)
				if clientIP != "" {
					pr.Out.Header.Set("X-Forwarded-For", clientIP)
					pr.Out.Header.Set("X-Real-IP", clientIP)
				}

				// Route-level header injection. Values of the form
				// "${req.HEADER-NAME}" copy the named header from the inbound
				// request; all other values are used verbatim.
				for hdr, tpl := range route.AddRequestHeaders {
					pr.Out.Header.Set(hdr, resolveHeaderTpl(tpl, pr.In))
				}
			},
			ErrorHandler: func(rw http.ResponseWriter, req *http.Request, err error) {
				netErr = err
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

		attemptStart := time.Now()
		rp.ServeHTTP(dst, r)
		p.releaseInstance(backend.Name, selected)

		p.metrics.ObserveUpstreamLatency(backendName, time.Since(attemptStart))
		if selected.circuit != nil {
			p.metrics.SetCircuitState(backendName, selected.URL.String(), selected.circuit.State())
		}

		// Non-retryable request: the response has already streamed to the client.
		if !retryEligible {
			return
		}

		lastBuf = buf

		// Once the buffer committed (response exceeded the cap and streamed
		// through), bytes are on the wire and the request can no longer be retried.
		if buf.committed {
			return
		}

		isNetErr := netErr != nil
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

	if lastBuf != nil {
		lastBuf.flushTo(w)
	}
}

// resolveHeaderTpl resolves a header value template for add_request_headers.
// Templates of the form "${req.HEADER-NAME}" are replaced with the value of
// that header from the inbound request (empty string when absent). All other
// values are returned unchanged.
func resolveHeaderTpl(tpl string, in *http.Request) string {
	const prefix = "${req."
	if !strings.HasPrefix(tpl, prefix) || !strings.HasSuffix(tpl, "}") {
		return tpl
	}
	name := tpl[len(prefix) : len(tpl)-1]
	return in.Header.Get(name)
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
