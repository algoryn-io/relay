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
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"algoryn.io/relay/internal/config"
	"algoryn.io/relay/internal/discovery"
	"algoryn.io/relay/internal/httpx"
)

type instanceState struct {
	URL         *url.URL
	Healthy     bool // guarded by Proxy.mu (written by health loop / drain)
	LastChecked time.Time
	// activeRequests is updated lock-free on the hot path (select/release).
	activeRequests atomic.Int64
	weight         int             // effective weight >= 1
	circuit        *CircuitBreaker // nil when circuit breaker is disabled
	outlier        *outlierState   // nil when passive detection is disabled
}

// HealthNotifier receives backend health state changes from the health check loop.
type HealthNotifier interface {
	NotifyBackendHealth(backend, instance string, healthy bool)
}

// ProxyMetrics receives backend-centric resilience metrics. Implemented by the
// observability collector and wired via SetMetrics; nil is safe (no-op).
type ProxyMetrics interface {
	ObserveUpstreamLatency(backend string, d time.Duration)
	RecordRetry(backend, reason string)
	RecordRetryBudgetExhausted(backend string)
	SetCircuitState(backend, instance, state string)
	SetBulkheadInFlight(backend string, n int)
	RecordBulkheadRejected(backend string)
	RecordOutlierEjection(backend, instance, reason string)
	RecordOutlierRecovery(backend, instance, reason string)
	SetOutlierEjected(backend, instance string, ejected bool)
}

// nopMetrics is the default no-op ProxyMetrics so call sites never nil-check.
type nopMetrics struct{}

func (nopMetrics) ObserveUpstreamLatency(string, time.Duration) {}
func (nopMetrics) RecordRetry(string, string)                   {}
func (nopMetrics) RecordRetryBudgetExhausted(string)            {}
func (nopMetrics) SetCircuitState(string, string, string)       {}
func (nopMetrics) SetBulkheadInFlight(string, int)              {}
func (nopMetrics) RecordBulkheadRejected(string)                {}
func (nopMetrics) RecordOutlierEjection(string, string, string) {}
func (nopMetrics) RecordOutlierRecovery(string, string, string) {}
func (nopMetrics) SetOutlierEjected(string, string, bool)       {}

type outcomeRoundTripper struct {
	base   http.RoundTripper
	status *int
	err    *error
}

func (t outcomeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	*t.err = err
	if resp != nil {
		*t.status = resp.StatusCode
	}
	return resp, err
}

type Proxy struct {
	cancel            context.CancelFunc
	ctx               context.Context
	closeOnce         sync.Once
	mu                sync.RWMutex
	logger            *slog.Logger
	healthNotifier    HealthNotifier
	backends          map[string]config.BackendRuntime
	instances         map[string][]*instanceState
	roundRobin        map[string]*atomic.Uint64 // per-backend; map is read-only after New
	backendTransports map[string]http.RoundTripper
	defaultTransport  http.RoundTripper // tuned fallback; rarely used
	bulkheads         map[string]*bulkhead
	retryBudgets      map[string]*retryBudget // per-backend; nil entry = unlimited
	wsIdleTimeout     time.Duration           // 0 = no WebSocket idle timeout
	metricsMu         sync.RWMutex
	metrics           ProxyMetrics
	clock             clock
	resolver          discovery.Resolver
	discoveryTTL      map[string]time.Duration // last observed DNS TTL per backend
	healthWG          sync.WaitGroup           // tracks health-check goroutines for clean shutdown
	discoveryWG       sync.WaitGroup           // tracks DNS discovery goroutines for clean shutdown
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
	p.metricsMu.Lock()
	p.metrics = m
	p.metricsMu.Unlock()
}

func (p *Proxy) metricsSink() ProxyMetrics {
	p.metricsMu.RLock()
	m := p.metrics
	p.metricsMu.RUnlock()
	return m
}

func New(rt *config.RuntimeConfig, logger *slog.Logger) (*Proxy, error) {
	return newProxy(rt, logger, &discovery.DNSResolver{})
}

// NewWithResolver is like New but injects a DNS resolver (used by tests).
func NewWithResolver(rt *config.RuntimeConfig, logger *slog.Logger, resolver discovery.Resolver) (*Proxy, error) {
	if resolver == nil {
		resolver = &discovery.DNSResolver{}
	}
	return newProxy(rt, logger, resolver)
}

func newProxy(rt *config.RuntimeConfig, logger *slog.Logger, resolver discovery.Resolver) (*Proxy, error) {
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
		roundRobin:        make(map[string]*atomic.Uint64, len(rt.Backends)),
		backendTransports: make(map[string]http.RoundTripper, len(rt.Backends)),
		defaultTransport:  newBaseTransport(),
		bulkheads:         make(map[string]*bulkhead, len(rt.Backends)),
		retryBudgets:      make(map[string]*retryBudget, len(rt.Backends)),
		metrics:           nopMetrics{},
		clock:             realClock{},
		resolver:          resolver,
		discoveryTTL:      make(map[string]time.Duration, len(rt.Backends)),
	}

	for name, backend := range rt.Backends {
		if backend.Bulkhead.MaxConcurrent > 0 {
			p.bulkheads[name] = newBulkhead(backend.Bulkhead.MaxConcurrent)
		}
		if backend.Retry.BudgetRatio > 0 {
			p.retryBudgets[name] = newRetryBudget(backend.Retry.BudgetTokens, backend.Retry.BudgetRatio)
		}

		// Every backend gets its own tuned transport (with TLS applied when
		// configured, or a cleartext HTTP/2 transport for h2c) so connection
		// pooling is never left to http.DefaultTransport.
		tr, trErr := buildBackendTransport(backend.Protocol, backend.TLS)
		if trErr != nil {
			p.Close()
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
				outlier:     newInstanceOutlier(backend.OutlierDetection),
			})
		}

		p.instances[name] = states
		p.roundRobin[name] = new(atomic.Uint64)

		if backend.Discovery != nil {
			// Initial resolve before serving; the loop continues on TTL/refresh.
			p.refreshDiscoveredBackend(name, backend.Discovery)
			p.startDiscovery(name, backend.Discovery)
		}

		if hasHealthCheck {
			p.healthWG.Add(1)
			go p.healthLoop(name, backend.HealthCheck)
		}
	}

	return p, nil
}

func (p *Proxy) Close() {
	if p == nil {
		return
	}
	p.closeOnce.Do(func() {
		if p.cancel != nil {
			p.cancel()
		}
		// Wait for health-check and DNS discovery goroutines to observe the
		// cancellation and exit, so no background work outlives the proxy after
		// a reload or shutdown.
		p.healthWG.Wait()
		p.discoveryWG.Wait()
		closeTransport := func(rt http.RoundTripper) {
			if tr, ok := rt.(interface{ CloseIdleConnections() }); ok {
				tr.CloseIdleConnections()
			}
		}
		for _, tr := range p.backendTransports {
			closeTransport(tr)
		}
		closeTransport(p.defaultTransport)
	})
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request, route *config.RouteRuntime) {
	if p == nil || route == nil {
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

	// Pick primary or a secondary failover backend (and acquire its bulkhead).
	backend, releaseBackend, err := p.resolveRouteBackend(route)
	if err != nil {
		if errors.Is(err, errBulkheadFull) {
			if p.logger != nil {
				p.logger.Warn("bulkhead full across failover group",
					"route", route.Name,
					"primary", route.BackendName,
				)
			}
			httpx.WriteError(w, http.StatusServiceUnavailable, "bulkhead_full")
			return
		}
		if errors.Is(err, errAllCircuitsOpen) {
			httpx.WriteError(w, http.StatusServiceUnavailable, "circuit_open")
			return
		}
		httpx.WriteError(w, http.StatusBadGateway, "bad_gateway")
		return
	}
	defer releaseBackend()
	backendName := backend.Name

	// WebSocket (and other protocol upgrades) bypass the retry loop and
	// responseBuffer: the real ResponseWriter must remain accessible for
	// http.Hijacker, and replaying a half-established connection is not possible.
	if isWebSocketUpgrade(r) {
		p.serveWebSocket(w, r, route, backend, clientIP, proto, originalHost)
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

	// h2c backends carry gRPC and other HTTP/2 streams: responses use trailers and
	// are frequently long-lived/bidirectional, which the retry response buffer
	// cannot capture. Stream straight through and let the gRPC client handle
	// retries. FlushInterval -1 flushes each write immediately for streaming.
	h2c := backend.IsH2C()

	// A request is retry-eligible only when more than one attempt is configured,
	// at least one retry condition is set, and the method is safe (or unsafe
	// methods are explicitly allowed). When it is not eligible there is no reason
	// to buffer: the response streams straight to the client. This keeps the hot
	// path allocation-free and preserves streaming/SSE for the common case.
	retryEligible := !h2c &&
		maxAttempts > 1 &&
		len(retry.On) > 0 &&
		(retry.AllowUnsafe || isSafeMethod(r.Method))
	if !retryEligible {
		maxAttempts = 1
	}

	// Retry budget: every retry-eligible request funds the token bucket; each
	// retry withdraws a token below. This caps retries at a fraction of traffic
	// so a failing backend cannot amplify its own load.
	budget := p.retryBudgets[backendName]
	if retryEligible && budget != nil {
		budget.deposit()
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
		var upstreamStatus int
		var upstreamErr error
		transport = outcomeRoundTripper{base: transport, status: &upstreamStatus, err: &upstreamErr}

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
			// Immediate flushing keeps gRPC/HTTP-2 streams (and SSE) responsive
			// instead of waiting for the copy buffer to fill.
			FlushInterval: flushIntervalFor(h2c),
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

				// Route-level header injection. Values of the form
				// "${req.HEADER-NAME}" copy the named header from the inbound
				// request; all other values are used verbatim.
				for hdr, tpl := range route.AddRequestHeaders {
					pr.Out.Header.Set(hdr, resolveHeaderTpl(tpl, pr.In))
				}
				// Relay-owned forwarding and mTLS identity values are applied
				// last so neither inbound nor route-injected values can spoof them.
				applyRelayOwnedHeaders(pr.Out.Header, pr.In, route, backend, target, clientIP, proto, originalHost)
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

		p.metricsSink().ObserveUpstreamLatency(backendName, time.Since(attemptStart))
		if failure, count := passiveOutlierOutcome(upstreamStatus, upstreamErr); count {
			p.recordOutlierOutcome(backendName, selected, failure, false)
		}
		if selected.circuit != nil {
			p.metricsSink().SetCircuitState(backendName, selected.URL.String(), selected.circuit.State())
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

		// Retry budget gate: suppress the retry when the bucket is empty so a
		// failing backend cannot be flooded with retries during an outage.
		if budget != nil && !budget.withdraw() {
			p.metricsSink().RecordRetryBudgetExhausted(backendName)
			if p.logger != nil {
				p.logger.Warn("retry suppressed: budget exhausted", "backend", backendName)
			}
			break
		}

		// Record the retry on the active OTel span so it appears in traces.
		reason := "5xx"
		if isNetErr {
			reason = "network_error"
		}
		p.metricsSink().RecordRetry(backendName, reason)
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

func passiveOutlierOutcome(status int, err error) (failure, count bool) {
	if errors.Is(err, context.Canceled) {
		return false, false
	}
	return err != nil || status >= 500, true
}

// flushIntervalFor returns the ReverseProxy flush interval. h2c (gRPC/streaming)
// backends flush every write immediately (-1); others use the default (0), which
// lets Go pick an efficient buffered cadence.
func flushIntervalFor(h2c bool) time.Duration {
	if h2c {
		return -1
	}
	return 0
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

func (p *Proxy) releaseInstance(_ string, selected *instanceState) {
	if selected == nil {
		return
	}
	// Lock-free: each select does exactly one Add(1) and each release one Add(-1),
	// so the counter stays balanced. Guard against a stray double-release.
	if selected.activeRequests.Add(-1) < 0 {
		selected.activeRequests.Store(0)
	}
}
