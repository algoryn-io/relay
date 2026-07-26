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
	c.AddRateLimitMemoryBuckets(7)
	c.RecordRateLimitMemoryEviction()

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
		`relay_rate_limit_memory_buckets 7`,
		`relay_rate_limit_memory_evictions_total 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape missing %q", want)
		}
	}
}

func TestPrometheusRecordsBoundedReloadMetrics(t *testing.T) {
	t.Parallel()
	c := NewPrometheusCollector()
	c.RecordConfigReload("failure", "validate")
	c.RecordConfigReload("success", "observability")

	rec := httptest.NewRecorder()
	c.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	for _, want := range []string{
		`relay_config_reload_total{result="failure",stage="validate"} 1`,
		`relay_config_reload_total{result="success",stage="observability"} 1`,
		"relay_config_last_successful_reload_timestamp_seconds ",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape missing %q", want)
		}
	}
	if strings.Contains(body, "error=") {
		t.Fatal("reload metrics exposed an unbounded error label")
	}
}
