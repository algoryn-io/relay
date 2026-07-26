package observability

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOperationalEventsTransitionsAndBoundedMetrics(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	metrics := NewPrometheusCollector()
	events := NewOperationalEvents(logger, metrics)
	delivered := make(chan FabricDispatchItem, 8)
	dispatcher := NewEventDispatcher(8, logger, func(item FabricDispatchItem) {
		delivered <- item
	})
	defer dispatcher.Close()
	events.SetFabric(dispatcher, "relay-test")

	events.RecordRateLimitRedisResult("primary", false, true)
	events.RecordRateLimitFailOpenBypass()
	events.RecordRateLimitRedisResult("primary", false, true)
	events.RecordRateLimitFailOpenBypass()
	events.RecordRateLimitRedisResult("primary", true, true)
	events.RecordRateLimitRedisResult("primary", true, true)
	events.RecordRateLimitRedisResult("primary", false, false)
	events.RecordRateLimitRedisResult("primary", false, false)
	events.RecordRateLimitRedisResult("primary", true, false)
	events.RecordRateLimitMemoryEviction()
	events.RecordRateLimitMemoryEviction()

	items := make([]FabricDispatchItem, 0, 6)
	for range 6 {
		items = append(items, <-delivered)
	}
	for _, item := range items {
		if item.Event == nil || item.Event.GetThresholdViolated() == nil {
			t.Fatal("missing bounded Fabric operational payload")
		}
	}
	wantCodes := []string{
		EventCodeRedisDegraded,
		EventCodeFailOpenBypass,
		EventCodeRedisRecovered,
		EventCodeRedisUnavailable,
		EventCodeRedisRecovered,
		EventCodeMemoryEvictionPressure,
	}
	for i, want := range wantCodes {
		if got := items[i].Event.GetThresholdViolated().GetDescription(); got != want {
			t.Fatalf("event %d code = %q, want %q", i, got, want)
		}
	}

	body := scrapeOperationalMetrics(t, metrics)
	for _, want := range []string{
		`relay_rate_limit_redis_checks_total{result="error"} 4`,
		`relay_rate_limit_redis_checks_total{result="success"} 3`,
		`relay_rate_limit_fail_open_bypass_total 2`,
		`relay_rate_limit_memory_evictions_total 2`,
		`relay_rate_limit_redis_available 1`,
		`relay_rate_limit_redis_state 0`,
		`relay_operational_events_total{code="relay.rate_limit.redis.degraded"} 1`,
		`relay_operational_events_total{code="relay.rate_limit.redis.unavailable"} 1`,
		`relay_operational_events_total{code="relay.rate_limit.redis.recovered"} 2`,
		`relay_operational_events_total{code="relay.rate_limit.memory_eviction_pressure"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape missing %q", want)
		}
	}
	if strings.Contains(body, "error=") || strings.Contains(body, "redis://") {
		t.Fatal("metrics contain an unbounded or sensitive label")
	}
	if strings.Contains(logs.String(), "redis://") || strings.Contains(logs.String(), "secret") {
		t.Fatal("operational logs contain sensitive data")
	}
}

func TestConfigReloadEventsAreTransitionOnlyButAttemptsAlwaysCount(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	metrics := NewPrometheusCollector()
	events := NewOperationalEvents(slog.New(slog.NewJSONHandler(&logs, nil)), metrics)

	events.RecordConfigReload("failure", "validate")
	events.RecordConfigReload("failure", "validate")
	events.RecordConfigReload("success", "observability")

	body := scrapeOperationalMetrics(t, metrics)
	for _, want := range []string{
		`relay_config_reload_total{result="failure",stage="validate"} 2`,
		`relay_config_reload_total{result="success",stage="observability"} 1`,
		`relay_operational_events_total{code="relay.config_reload.failed"} 1`,
		`relay_operational_events_total{code="relay.config_reload.succeeded"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape missing %q", want)
		}
	}
	if strings.Count(logs.String(), EventCodeConfigReloadFailed) != 1 {
		t.Fatalf("repeated failure was not suppressed: %s", logs.String())
	}
}

func TestRedisAggregateDoesNotRecoverWhileAnotherStoreIsDown(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	metrics := NewPrometheusCollector()
	events := NewOperationalEvents(slog.New(slog.NewJSONHandler(&logs, nil)), metrics)
	events.ConfigureRateLimitRedisSources([]string{"orders", "accounts"})

	events.RecordRateLimitRedisResult("orders", false, false)
	events.RecordRateLimitRedisResult("accounts", true, false)
	if body := scrapeOperationalMetrics(t, metrics); !strings.Contains(body, "relay_rate_limit_redis_state 2") {
		t.Fatalf("aggregate Redis state did not remain unavailable: %s", body)
	}
	if strings.Contains(logs.String(), EventCodeRedisRecovered) {
		t.Fatal("healthy store caused a false aggregate recovery")
	}
	events.RecordRateLimitRedisResult("orders", true, false)
	if strings.Count(logs.String(), EventCodeRedisRecovered) != 1 {
		t.Fatalf("aggregate recovery count is not one: %s", logs.String())
	}
}

func scrapeOperationalMetrics(t *testing.T, metrics *PrometheusCollector) string {
	t.Helper()
	rec := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	return rec.Body.String()
}
