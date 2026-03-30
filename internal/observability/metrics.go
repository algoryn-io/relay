package observability

import (
	"encoding/json"
	"math"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"
)

const defaultLatencySamples = 100

type Metrics struct {
	mu sync.RWMutex

	totalRequests uint64
	byRoute       map[string]uint64
	byStatus      map[int]uint64
	latency       map[string][]time.Duration

	maxLatencySamples int
}

func NewMetrics(maxLatencySamples int) *Metrics {
	if maxLatencySamples <= 0 {
		maxLatencySamples = defaultLatencySamples
	}
	return &Metrics{
		byRoute:           make(map[string]uint64),
		byStatus:          make(map[int]uint64),
		latency:           make(map[string][]time.Duration),
		maxLatencySamples: maxLatencySamples,
	}
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

	m.mu.Lock()
	defer m.mu.Unlock()

	m.totalRequests++
	m.byRoute[route]++
	m.byStatus[status]++

	samples := append(m.latency[route], latency)
	if len(samples) > m.maxLatencySamples {
		overflow := len(samples) - m.maxLatencySamples
		copy(samples, samples[overflow:])
		samples = samples[:m.maxLatencySamples]
	}
	m.latency[route] = samples
}

func (m *Metrics) Snapshot() map[string]any {
	if m == nil {
		return map[string]any{
			"total_requests": uint64(0),
			"routes":         map[string]any{},
			"status_codes":   map[string]uint64{},
		}
	}

	m.mu.RLock()
	total := m.totalRequests
	byRoute := make(map[string]uint64, len(m.byRoute))
	for route, count := range m.byRoute {
		byRoute[route] = count
	}
	byStatus := make(map[int]uint64, len(m.byStatus))
	for status, count := range m.byStatus {
		byStatus[status] = count
	}
	latencyCopy := make(map[string][]time.Duration, len(m.latency))
	for route, samples := range m.latency {
		cloned := make([]time.Duration, len(samples))
		copy(cloned, samples)
		latencyCopy[route] = cloned
	}
	m.mu.RUnlock()

	routes := make(map[string]any, len(byRoute))
	for route, count := range byRoute {
		samples := latencyCopy[route]
		routes[route] = map[string]any{
			"requests":       count,
			"avg_latency_ms": avgLatencyMS(samples),
			"p95_latency_ms": p95LatencyMS(samples),
		}
	}

	statusCodes := make(map[string]uint64, len(byStatus))
	for status, count := range byStatus {
		statusCodes[strconv.Itoa(status)] = count
	}

	return map[string]any{
		"total_requests": total,
		"routes":         routes,
		"status_codes":   statusCodes,
	}
}

func MetricsHandler(metrics *Metrics) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusMethodNotAllowed)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":  "method_not_allowed",
				"status": "error",
			})
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
