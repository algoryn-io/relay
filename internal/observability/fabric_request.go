package observability

import (
	"fmt"
	"time"

	fab "algoryn.io/fabric"
	fabricevents "algoryn.io/fabric/events"
	fabricv1 "algoryn.io/fabric/gen/go/fabric/v1"
	fabricmetrics "algoryn.io/fabric/metrics"

	"google.golang.org/protobuf/types/known/timestamppb"
)

const fabricRelayTag = "relay"

// BuildRequestFabricTelemetry maps one proxied HTTP exchange to Fabric protobuf messages.
// relayServiceName is emitted on fabricv1.Event.source (Relay deployment identity).
// routeName identifies the matched route configuration.
func BuildRequestFabricTelemetry(
	relayServiceName string,
	routeName string,
	method string,
	path string,
	status int,
	latency time.Duration,
	started time.Time,
) (*fabricv1.MetricSnapshot, *fabricv1.Event) {
	if relayServiceName == "" {
		relayServiceName = fabricmetrics.SourceRelay
	}
	if status == 0 {
		status = 200
	}
	if routeName == "" {
		routeName = "unknown"
	}

	snapGo := singleRequestMetricSnapshot(relayServiceName, routeName, method, path, status, latency, started)
	snapProto := fab.MetricSnapshotToProto(snapGo)

	var failed int64
	if status >= 400 {
		failed = 1
	}
	sec := latency.Seconds()
	rps := 0.0
	if sec > 0 {
		rps = 1.0 / sec
	}
	var errRate float64
	if status >= 400 {
		errRate = 1
	}

	// EVENT_TYPE_RUN_COMPLETED with a one-request RunSummary is the closest Fabric envelope
	// for per-exchange gateway telemetry until a dedicated metric-event type exists.
	runID := fmt.Sprintf("relay-req-%d", started.UnixNano())
	payload := fabricevents.RunCompletedPayload{
		RunID:    runID,
		Service:  routeName,
		Passed:   status < 400,
		Duration: latency,
		Summary: fabricevents.RunSummary{
			Total:     1,
			Failed:    failed,
			RPS:       rps,
			ErrorRate: errRate,
			P99Ms:     float64(latency.Milliseconds()),
		},
	}

	evt := &fabricv1.Event{
		Id:        runID,
		Type:      fabricv1.EventType_EVENT_TYPE_RUN_COMPLETED,
		Source:    relayServiceName,
		Timestamp: timestamppb.Now(),
		Payload: &fabricv1.Event_RunCompleted{
			RunCompleted: fab.RunCompletedPayloadToProto(&payload),
		},
	}
	return snapProto, evt
}

func singleRequestMetricSnapshot(
	relayServiceName string,
	routeName string,
	method string,
	path string,
	status int,
	latency time.Duration,
	started time.Time,
) fabricmetrics.MetricSnapshot {
	var failed int64
	if status >= 400 {
		failed = 1
	}
	sec := latency.Seconds()
	rps := 0.0
	if sec > 0 {
		rps = 1.0 / sec
	}

	lat := fabricmetrics.LatencyStats{
		Min:  latency,
		Mean: latency,
		P50:  latency,
		P90:  latency,
		P95:  latency,
		P99:  latency,
		Max:  latency,
	}

	labels := map[string]string{
		"route":  routeName,
		"method": method,
		"path":   path,
	}
	if relayServiceName != "" {
		labels[fabricRelayTag] = relayServiceName
	}

	return fabricmetrics.MetricSnapshot{
		Source:      fabricmetrics.SourceRelay,
		Service:     routeName,
		Timestamp:   started,
		Window:      latency,
		Total:       1,
		Failed:      failed,
		RPS:         rps,
		Latency:     lat,
		StatusCodes: map[int]int64{status: 1},
		Labels:      labels,
	}
}

// BuildServiceRegisteredFabricEvent builds EVENT_TYPE_SERVICE_REGISTERED for upstream instances Relay serves.
func BuildServiceRegisteredFabricEvent(relayServiceName, backendName, instanceURL string) *fabricv1.Event {
	if relayServiceName == "" {
		relayServiceName = fabricmetrics.SourceRelay
	}
	payload := fabricevents.ServiceRegisteredPayload{
		Name:    backendName,
		Address: instanceURL,
		Tags: map[string]string{
			fabricRelayTag: relayServiceName,
			"kind":         "backend_instance",
		},
	}
	return &fabricv1.Event{
		Id:        fmt.Sprintf("relay-svc-%s-%d", backendName, time.Now().UnixNano()),
		Type:      fabricv1.EventType_EVENT_TYPE_SERVICE_REGISTERED,
		Source:    relayServiceName,
		Timestamp: timestamppb.Now(),
		Payload: &fabricv1.Event_ServiceRegistered{
			ServiceRegistered: fab.ServiceRegisteredPayloadToProto(&payload),
		},
	}
}
