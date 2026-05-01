package observability

import (
	"testing"
	"time"

	fabricv1 "algoryn.io/fabric/gen/go/fabric/v1"
	fabricmetrics "algoryn.io/fabric/metrics"
)

func TestBuildRequestFabricTelemetry_SourceAndSnapshot(t *testing.T) {
	t.Parallel()

	started := time.Date(2026, 1, 10, 12, 0, 0, 0, time.UTC)
	latency := 12 * time.Millisecond

	snap, evt := BuildRequestFabricTelemetry(
		"relay-edge-1",
		"orders-route",
		"GET",
		"/api/orders",
		200,
		latency,
		started,
	)

	if snap.GetSource() != fabricmetrics.SourceRelay {
		t.Fatalf("snapshot source = %q", snap.GetSource())
	}
	if snap.GetService() != "orders-route" {
		t.Fatalf("snapshot service = %q", snap.GetService())
	}
	if snap.GetTotal() != 1 || snap.GetFailed() != 0 {
		t.Fatalf("totals: total=%d failed=%d", snap.GetTotal(), snap.GetFailed())
	}
	if snap.GetLabels()["method"] != "GET" || snap.GetLabels()["route"] != "orders-route" {
		t.Fatalf("labels = %v", snap.GetLabels())
	}

	if evt.GetSource() != "relay-edge-1" {
		t.Fatalf("event source = %q", evt.GetSource())
	}
	if evt.GetType() != fabricv1.EventType_EVENT_TYPE_RUN_COMPLETED {
		t.Fatalf("type = %v", evt.GetType())
	}
	p := evt.GetRunCompleted()
	if p == nil || p.GetService() != "orders-route" || !p.GetPassed() {
		t.Fatalf("run completed = %+v", p)
	}
}

func TestBuildServiceRegisteredFabricEvent(t *testing.T) {
	t.Parallel()

	evt := BuildServiceRegisteredFabricEvent("relay-prod", "orders-backend", "http://10.0.0.5:8080")
	if evt.GetSource() != "relay-prod" {
		t.Fatalf("source = %q", evt.GetSource())
	}
	if evt.GetType() != fabricv1.EventType_EVENT_TYPE_SERVICE_REGISTERED {
		t.Fatalf("type = %v", evt.GetType())
	}
	sr := evt.GetServiceRegistered()
	if sr.GetName() != "orders-backend" || sr.GetAddress() != "http://10.0.0.5:8080" {
		t.Fatalf("payload = %+v", sr)
	}
}
