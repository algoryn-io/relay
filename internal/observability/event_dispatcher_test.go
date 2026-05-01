package observability

import (
	"sync/atomic"
	"testing"

	fabricv1 "algoryn.io/fabric/gen/go/fabric/v1"
	fabricmetrics "algoryn.io/fabric/metrics"
)

func TestEventDispatcher_DeliversItems(t *testing.T) {
	t.Parallel()

	var n atomic.Int32
	d := NewEventDispatcher(8, nil, func(item FabricDispatchItem) {
		if item.Event != nil {
			n.Add(1)
		}
		if item.Snapshot != nil {
			n.Add(1)
		}
	})

	d.TryEnqueue(FabricDispatchItem{
		Snapshot: &fabricv1.MetricSnapshot{Source: fabricmetrics.SourceRelay, Total: 1},
	})
	d.TryEnqueue(FabricDispatchItem{
		Event: &fabricv1.Event{Source: "edge-relay", Type: fabricv1.EventType_EVENT_TYPE_SERVICE_REGISTERED},
	})

	d.Close()

	if got := n.Load(); got != 2 {
		t.Fatalf("handler calls = %d, want 2", got)
	}
}

func TestEventDispatcher_CloseIsIdempotent(t *testing.T) {
	t.Parallel()

	d := NewEventDispatcher(4, nil, nil)
	d.Close()
	d.Close()
}
