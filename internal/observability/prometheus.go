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
	requestsTotal   *prometheus.CounterVec
	requestDuration *prometheus.HistogramVec
	activeRequests  *prometheus.GaugeVec
	backendHealthy  *prometheus.GaugeVec
	registry        *prometheus.Registry
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

	reg.MustRegister(requestsTotal, requestDuration, activeRequests, backendHealthy)

	return &PrometheusCollector{
		requestsTotal:   requestsTotal,
		requestDuration: requestDuration,
		activeRequests:  activeRequests,
		backendHealthy:  backendHealthy,
		registry:        reg,
	}
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
