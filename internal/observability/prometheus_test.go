package observability

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPrometheusExposesResilienceMetrics(t *testing.T) {
	t.Parallel()

	c := NewPrometheusCollector()
	c.ObserveUpstreamLatency("orders", 12*time.Millisecond)
	c.RecordRetry("orders", "5xx")
	c.SetCircuitState("orders", "http://1.2.3.4:8080", "open")
	c.SetBulkheadInFlight("orders", 3)
	c.RecordBulkheadRejected("orders")

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	c.Handler().ServeHTTP(rec, req)

	body := rec.Body.String()
	for _, want := range []string{
		"relay_upstream_duration_seconds",
		`relay_retry_total{backend="orders",reason="5xx"} 1`,
		`relay_circuit_breaker_state{backend="orders",instance="http://1.2.3.4:8080"} 2`,
		`relay_bulkhead_in_flight{backend="orders"} 3`,
		`relay_bulkhead_rejected_total{backend="orders"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape missing %q", want)
		}
	}
}
