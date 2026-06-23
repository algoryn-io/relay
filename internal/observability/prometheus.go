package observability

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// PrometheusCollector records per-request metrics in Prometheus format and tracks
// backend health state. It satisfies proxy.HealthNotifier so the health loop can
// push updates without the proxy package importing this one.
type PrometheusCollector struct {
	requestsTotal    *prometheus.CounterVec
	requestDuration  *prometheus.HistogramVec
	activeRequests   *prometheus.GaugeVec
	backendHealthy   *prometheus.GaugeVec
	upstreamDuration *prometheus.HistogramVec
	retryTotal       *prometheus.CounterVec
	circuitState     *prometheus.GaugeVec
	bulkheadInFlight *prometheus.GaugeVec
	bulkheadRejected *prometheus.CounterVec
	registry         *prometheus.Registry
}

func NewPrometheusCollector() *PrometheusCollector {
	reg := prometheus.NewRegistry()

	requestsTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "relay_requests_total",
		Help: "Total HTTP requests processed, partitioned by route, method and status code.",
	}, []string{"route", "method", "status_code"})

	requestDuration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "relay_request_duration_seconds",
		Help:    "HTTP request latency in seconds.",
		Buckets: prometheus.DefBuckets,
	}, []string{"route", "method"})

	activeRequests := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "relay_active_requests",
		Help: "Number of HTTP requests currently being processed.",
	}, []string{"route"})

	backendHealthy := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "relay_backend_healthy",
		Help: "Backend instance health: 1 = healthy, 0 = unhealthy.",
	}, []string{"backend", "instance"})

	upstreamDuration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "relay_upstream_duration_seconds",
		Help:    "Upstream (backend) response latency in seconds, per attempt.",
		Buckets: prometheus.DefBuckets,
	}, []string{"backend"})

	retryTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "relay_retry_total",
		Help: "Total request retries, partitioned by backend and reason.",
	}, []string{"backend", "reason"})

	circuitState := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "relay_circuit_breaker_state",
		Help: "Circuit breaker state per instance: 0 = closed, 1 = half_open, 2 = open.",
	}, []string{"backend", "instance"})

	bulkheadInFlight := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "relay_bulkhead_in_flight",
		Help: "In-flight requests currently occupying a backend bulkhead slot.",
	}, []string{"backend"})

	bulkheadRejected := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "relay_bulkhead_rejected_total",
		Help: "Total requests rejected because the backend bulkhead was full.",
	}, []string{"backend"})

	reg.MustRegister(
		requestsTotal, requestDuration, activeRequests, backendHealthy,
		upstreamDuration, retryTotal, circuitState, bulkheadInFlight, bulkheadRejected,
	)

	return &PrometheusCollector{
		requestsTotal:    requestsTotal,
		requestDuration:  requestDuration,
		activeRequests:   activeRequests,
		backendHealthy:   backendHealthy,
		upstreamDuration: upstreamDuration,
		retryTotal:       retryTotal,
		circuitState:     circuitState,
		bulkheadInFlight: bulkheadInFlight,
		bulkheadRejected: bulkheadRejected,
		registry:         reg,
	}
}

// ── proxy.ProxyMetrics implementation ────────────────────────────────────────

// ObserveUpstreamLatency records one backend attempt's latency.
func (c *PrometheusCollector) ObserveUpstreamLatency(backend string, d time.Duration) {
	if c == nil {
		return
	}
	c.upstreamDuration.WithLabelValues(backend).Observe(d.Seconds())
}

// RecordRetry counts a retry attempt for a backend with its trigger reason.
func (c *PrometheusCollector) RecordRetry(backend, reason string) {
	if c == nil {
		return
	}
	c.retryTotal.WithLabelValues(backend, reason).Inc()
}

// SetCircuitState reflects an instance's circuit breaker state as a gauge.
func (c *PrometheusCollector) SetCircuitState(backend, instance, state string) {
	if c == nil {
		return
	}
	var v float64
	switch state {
	case "half_open":
		v = 1
	case "open":
		v = 2
	}
	c.circuitState.WithLabelValues(backend, instance).Set(v)
}

// SetBulkheadInFlight reports the current bulkhead occupancy for a backend.
func (c *PrometheusCollector) SetBulkheadInFlight(backend string, n int) {
	if c == nil {
		return
	}
	c.bulkheadInFlight.WithLabelValues(backend).Set(float64(n))
}

// RecordBulkheadRejected counts a fail-fast bulkhead rejection.
func (c *PrometheusCollector) RecordBulkheadRejected(backend string) {
	if c == nil {
		return
	}
	c.bulkheadRejected.WithLabelValues(backend).Inc()
}

func (c *PrometheusCollector) RequestStarted(route string) {
	if c == nil {
		return
	}
	c.activeRequests.WithLabelValues(route).Inc()
}

func (c *PrometheusCollector) RequestFinished(route, method string, statusCode int, duration time.Duration) {
	if c == nil {
		return
	}
	c.activeRequests.WithLabelValues(route).Dec()
	c.requestsTotal.WithLabelValues(route, method, strconv.Itoa(statusCode)).Inc()
	c.requestDuration.WithLabelValues(route, method).Observe(duration.Seconds())
}

// NotifyBackendHealth satisfies proxy.HealthNotifier.
func (c *PrometheusCollector) NotifyBackendHealth(backend, instance string, healthy bool) {
	if c == nil {
		return
	}
	val := 0.0
	if healthy {
		val = 1.0
	}
	c.backendHealthy.WithLabelValues(backend, instance).Set(val)
}

func (c *PrometheusCollector) Handler() http.Handler {
	if c == nil {
		return http.NotFoundHandler()
	}
	return promhttp.HandlerFor(c.registry, promhttp.HandlerOpts{})
}
