package observability

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestMetricsRecordAndSnapshot(t *testing.T) {
	t.Parallel()

	m := NewMetrics(100)
	m.Record("orders-route", 200, 10*time.Millisecond)
	m.Record("orders-route", 200, 30*time.Millisecond)
	m.Record("payments-route", 500, 100*time.Millisecond)

	snapshot := m.Snapshot()

	total, ok := snapshot["total_requests"].(uint64)
	if !ok || total != 3 {
		t.Fatalf("total_requests = %v, want 3", snapshot["total_requests"])
	}

	routes, ok := snapshot["routes"].(map[string]any)
	if !ok {
		t.Fatalf("routes type = %T, want map[string]any", snapshot["routes"])
	}
	orders, ok := routes["orders-route"].(map[string]any)
	if !ok {
		t.Fatalf("orders-route type = %T, want map[string]any", routes["orders-route"])
	}
	if requests, ok := orders["requests"].(uint64); !ok || requests != 2 {
		t.Fatalf("orders requests = %v, want 2", orders["requests"])
	}
	if avg, ok := orders["avg_latency_ms"].(int64); !ok || avg != 20 {
		t.Fatalf("orders avg_latency_ms = %v, want 20", orders["avg_latency_ms"])
	}
	if p95, ok := orders["p95_latency_ms"].(int64); !ok || p95 != 30 {
		t.Fatalf("orders p95_latency_ms = %v, want 30", orders["p95_latency_ms"])
	}

	statusCodes, ok := snapshot["status_codes"].(map[string]uint64)
	if !ok {
		t.Fatalf("status_codes type = %T, want map[string]uint64", snapshot["status_codes"])
	}
	if statusCodes["200"] != 2 {
		t.Fatalf("status_codes[200] = %d, want 2", statusCodes["200"])
	}
	if statusCodes["500"] != 1 {
		t.Fatalf("status_codes[500] = %d, want 1", statusCodes["500"])
	}
}

func TestMetricsLatencyBoundedMemory(t *testing.T) {
	t.Parallel()

	m := NewMetrics(2)
	m.Record("orders-route", 200, 10*time.Millisecond)
	m.Record("orders-route", 200, 20*time.Millisecond)
	m.Record("orders-route", 200, 30*time.Millisecond)

	snapshot := m.Snapshot()
	routes := snapshot["routes"].(map[string]any)
	orders := routes["orders-route"].(map[string]any)
	if avg := orders["avg_latency_ms"].(int64); avg != 25 {
		t.Fatalf("avg_latency_ms = %d, want 25", avg)
	}
	if p95 := orders["p95_latency_ms"].(int64); p95 != 30 {
		t.Fatalf("p95_latency_ms = %d, want 30", p95)
	}
}

func TestMetricsMiddlewareRecords(t *testing.T) {
	t.Parallel()

	m := NewMetrics(100)
	mw := NewMetricsMiddleware(m, "orders-route")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))

	req := httptest.NewRequest(http.MethodPost, "/orders", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusCreated)
	}

	snapshot := m.Snapshot()
	if total := snapshot["total_requests"].(uint64); total != 1 {
		t.Fatalf("total_requests = %d, want 1", total)
	}
	statusCodes := snapshot["status_codes"].(map[string]uint64)
	if statusCodes["201"] != 1 {
		t.Fatalf("status_codes[201] = %d, want 1", statusCodes["201"])
	}
}

func TestLoggingMiddlewareNoPanic(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	mw := NewLoggingMiddleware(logger, "orders-route", "orders-backend")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/orders", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestMetricsHandlerReturnsSnapshotJSON(t *testing.T) {
	t.Parallel()

	m := NewMetrics(100)
	m.Record("orders-route", 200, 15*time.Millisecond)
	h := MetricsHandler(m)

	req := httptest.NewRequest(http.MethodGet, "/_relay/metrics", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content-type = %q, want application/json", got)
	}

	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if _, ok := body["total_requests"]; !ok {
		t.Fatal("snapshot missing total_requests")
	}
	if _, ok := body["routes"]; !ok {
		t.Fatal("snapshot missing routes")
	}
	if _, ok := body["status_codes"]; !ok {
		t.Fatal("snapshot missing status_codes")
	}
}
