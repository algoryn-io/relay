package observability

import (
	"encoding/json"
	"math"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"algoryn.io/relay/internal/httpx"
)

const defaultLatencySamples = 100

// routeMetrics holds the counters for a single route behind a small mutex, so
// requests to different routes never contend on a shared lock.
type routeMetrics struct {
	mu       sync.Mutex
	requests uint64
	statuses map[int]uint64
	latency  []time.Duration
}

// Metrics records a lightweight in-process summary for the JSON /_relay/metrics
// endpoint. It is sharded per route (via sync.Map) with only a per-route mutex,
// so the request hot path has no global lock. Prometheus remains the primary,
// lock-free metrics source.
type Metrics struct {
	total             atomic.Uint64
	routes            sync.Map // route(string) -> *routeMetrics
	maxLatencySamples int
}

func NewMetrics(maxLatencySamples int) *Metrics {
	if maxLatencySamples <= 0 {
		maxLatencySamples = defaultLatencySamples
	}
	return &Metrics{maxLatencySamples: maxLatencySamples}
}

func (m *Metrics) routeMetrics(route string) *routeMetrics {
	if v, ok := m.routes.Load(route); ok {
		return v.(*routeMetrics)
	}
	actual, _ := m.routes.LoadOrStore(route, &routeMetrics{statuses: make(map[int]uint64)})
	return actual.(*routeMetrics)
}

func (m *Metrics) Record(route string, status int, latency time.Duration) {
	if m == nil {
		return
	}
	if route == "" {
		route = "unknown"
	}
	if status == 0 {
		status = http.StatusOK
	}

	m.total.Add(1)
	rm := m.routeMetrics(route)

	rm.mu.Lock()
	rm.requests++
	rm.statuses[status]++
	samples := append(rm.latency, latency)
	if len(samples) > m.maxLatencySamples {
		overflow := len(samples) - m.maxLatencySamples
		copy(samples, samples[overflow:])
		samples = samples[:m.maxLatencySamples]
	}
	rm.latency = samples
	rm.mu.Unlock()
}

func (m *Metrics) Snapshot() map[string]any {
	if m == nil {
		return map[string]any{
			"total_requests": uint64(0),
			"routes":         map[string]any{},
			"status_codes":   map[string]uint64{},
		}
	}

	routes := map[string]any{}
	statusCodes := map[string]uint64{}

	m.routes.Range(func(k, v any) bool {
		route := k.(string)
		rm := v.(*routeMetrics)

		rm.mu.Lock()
		requests := rm.requests
		samples := make([]time.Duration, len(rm.latency))
		copy(samples, rm.latency)
		statuses := make(map[int]uint64, len(rm.statuses))
		for s, c := range rm.statuses {
			statuses[s] = c
		}
		rm.mu.Unlock()

		routes[route] = map[string]any{
			"requests":       requests,
			"avg_latency_ms": avgLatencyMS(samples),
			"p95_latency_ms": p95LatencyMS(samples),
		}
		for s, c := range statuses {
			statusCodes[strconv.Itoa(s)] += c
		}
		return true
	})

	return map[string]any{
		"total_requests": m.total.Load(),
		"routes":         routes,
		"status_codes":   statusCodes,
	}
}

func MetricsHandler(metrics *Metrics) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			httpx.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(metrics.Snapshot())
	})
}

func avgLatencyMS(samples []time.Duration) int64 {
	if len(samples) == 0 {
		return 0
	}
	var sum time.Duration
	for _, sample := range samples {
		sum += sample
	}
	return sum.Milliseconds() / int64(len(samples))
}

func p95LatencyMS(samples []time.Duration) int64 {
	if len(samples) == 0 {
		return 0
	}
	sorted := make([]time.Duration, len(samples))
	copy(sorted, samples)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i] < sorted[j]
	})
	index := int(math.Ceil(0.95*float64(len(sorted)))) - 1
	if index < 0 {
		index = 0
	}
	if index >= len(sorted) {
		index = len(sorted) - 1
	}
	return sorted[index].Milliseconds()
}
