package observability

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/trace"

	"algoryn.io/relay/internal/config"
)

type fakeLogExporter struct {
	mu      sync.Mutex
	records []sdklog.Record
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (f *fakeLogExporter) Export(_ context.Context, records []sdklog.Record) error {
	if f.started != nil {
		f.once.Do(func() { close(f.started) })
		<-f.release
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range records {
		f.records = append(f.records, records[i].Clone())
	}
	return nil
}

func (*fakeLogExporter) Shutdown(context.Context) error   { return nil }
func (*fakeLogExporter) ForceFlush(context.Context) error { return nil }

func TestOTLPLogSinkExportsAndPreservesTraceContext(t *testing.T) {
	exporter := &fakeLogExporter{}
	sink, err := newOTLPLogSinkWithExporter(context.Background(), config.OTLPLogsConfig{
		QueueSize: 8, BatchSize: 1, BatchTimeout: time.Millisecond, ExportTimeout: time.Second,
	}, exporter)
	if err != nil {
		t.Fatal(err)
	}
	traceID := trace.TraceID{1, 2, 3}
	spanID := trace.SpanID{4, 5, 6}
	ctx := trace.ContextWithSpanContext(context.Background(), trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: traceID, SpanID: spanID, TraceFlags: trace.FlagsSampled,
	}))
	record := slog.NewRecord(time.Now(), slog.LevelInfo, "request", 0)
	record.AddAttrs(slog.String("method", "GET"))
	sink.enqueue(ctx, record)
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}

	exporter.mu.Lock()
	defer exporter.mu.Unlock()
	if len(exporter.records) != 1 {
		t.Fatalf("exported records = %d, want 1", len(exporter.records))
	}
	if exporter.records[0].TraceID() != traceID || exporter.records[0].SpanID() != spanID {
		t.Fatalf("trace context not preserved: trace=%s span=%s", exporter.records[0].TraceID(), exporter.records[0].SpanID())
	}
}

func TestOTLPLogQueueOverflowDropsWithoutBlocking(t *testing.T) {
	before := otlpLogDrops.Load()
	exporter := &fakeLogExporter{started: make(chan struct{}), release: make(chan struct{})}
	sink, err := newOTLPLogSinkWithExporter(context.Background(), config.OTLPLogsConfig{
		QueueSize: 1, BatchSize: 1, BatchTimeout: time.Hour, ExportTimeout: time.Second,
	}, exporter)
	if err != nil {
		t.Fatal(err)
	}
	record := slog.NewRecord(time.Now(), slog.LevelInfo, "request", 0)
	sink.enqueue(context.Background(), record)
	<-exporter.started
	sink.enqueue(context.Background(), record)
	sink.enqueue(context.Background(), record)
	if got := otlpLogDrops.Load() - before; got != 1 {
		t.Fatalf("drops = %d, want 1", got)
	}
	close(exporter.release)
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
}
