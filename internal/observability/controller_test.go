package observability

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"algoryn.io/relay/internal/config"
)

type fakeLogWriter struct {
	mu      sync.Mutex
	buffer  bytes.Buffer
	started chan struct{}
	release chan struct{}
	closed  atomic.Bool
	once    sync.Once
}

func (w *fakeLogWriter) Write(p []byte) (int, error) {
	if w.started != nil {
		w.once.Do(func() { close(w.started) })
		<-w.release
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buffer.Write(p)
}

func (w *fakeLogWriter) Close() error {
	w.closed.Store(true)
	return nil
}

func (w *fakeLogWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buffer.String()
}

type fakeExporter struct {
	shutdown atomic.Bool
}

func (*fakeExporter) ExportSpans(context.Context, []sdktrace.ReadOnlySpan) error { return nil }
func (e *fakeExporter) Shutdown(context.Context) error {
	e.shutdown.Store(true)
	return nil
}

func TestControllerApplyDrainsOldWriter(t *testing.T) {
	oldWriter := &fakeLogWriter{started: make(chan struct{}), release: make(chan struct{})}
	newWriter := &fakeLogWriter{}
	writers := map[string]*fakeLogWriter{"old": oldWriter, "new": newWriter}
	logFactory := func(cfg config.LogsConfig) (*slog.Logger, io.Closer, error) {
		writer := writers[cfg.File]
		return slog.New(slog.NewJSONHandler(writer, nil)), writer, nil
	}
	oldExporter := &fakeExporter{}
	newExporter := &fakeExporter{}
	var exporterBuilds atomic.Int64
	exportFactory := func(context.Context, config.TracingConfig) (sdktrace.SpanExporter, error) {
		if exporterBuilds.Add(1) == 1 {
			return oldExporter, nil
		}
		return newExporter, nil
	}

	logging, err := newLoggerHandle(config.LogsConfig{File: "old"}, logFactory)
	if err != nil {
		t.Fatal(err)
	}
	tracing, err := newTracingHandle(context.Background(), config.TracingConfig{Enabled: true}, "old", exportFactory)
	if err != nil {
		t.Fatal(err)
	}
	controller := &Controller{Logging: logging, Tracing: tracing}
	t.Cleanup(func() { _ = controller.Close(context.Background()) })

	logDone := make(chan struct{})
	go func() {
		controller.Logging.Logger().Info("old record")
		close(logDone)
	}()
	<-oldWriter.started

	prepared, err := controller.Prepare(context.Background(), config.ObservabilityConfig{
		Logs:    config.LogsConfig{File: "new"},
		Tracing: config.TracingConfig{Enabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	applyDone := make(chan error, 1)
	go func() { applyDone <- controller.Apply(context.Background(), prepared) }()

	select {
	case <-applyDone:
		t.Fatal("Apply returned before the old log write drained")
	case <-time.After(20 * time.Millisecond):
	}
	if oldWriter.closed.Load() {
		t.Fatal("old writer closed while a log record was in flight")
	}
	close(oldWriter.release)
	<-logDone
	if err := <-applyDone; err != nil {
		t.Fatal(err)
	}
	if !oldWriter.closed.Load() || !oldExporter.shutdown.Load() {
		t.Fatal("retired logging/tracing resources were not closed")
	}

	controller.Logging.Logger().Info("new record")
	if got := newWriter.String(); !bytes.Contains([]byte(got), []byte(`"msg":"new record"`)) {
		t.Fatalf("new writer did not receive post-reload record: %q", got)
	}
}

func TestControllerPrepareFailureRollsBack(t *testing.T) {
	oldWriter := &fakeLogWriter{}
	candidateWriter := &fakeLogWriter{}
	logFactory := func(cfg config.LogsConfig) (*slog.Logger, io.Closer, error) {
		writer := oldWriter
		if cfg.File == "candidate" {
			writer = candidateWriter
		}
		return slog.New(slog.NewJSONHandler(writer, nil)), writer, nil
	}
	exportFailure := atomic.Bool{}
	exportFactory := func(context.Context, config.TracingConfig) (sdktrace.SpanExporter, error) {
		if exportFailure.Load() {
			return nil, errors.New("exporter init failed")
		}
		return &fakeExporter{}, nil
	}
	logging, err := newLoggerHandle(config.LogsConfig{File: "old"}, logFactory)
	if err != nil {
		t.Fatal(err)
	}
	tracing, err := newTracingHandle(context.Background(), config.TracingConfig{Enabled: true}, "old", exportFactory)
	if err != nil {
		t.Fatal(err)
	}
	controller := &Controller{Logging: logging, Tracing: tracing}
	t.Cleanup(func() { _ = controller.Close(context.Background()) })

	exportFailure.Store(true)
	if _, err := controller.Prepare(context.Background(), config.ObservabilityConfig{
		Logs:    config.LogsConfig{File: "candidate"},
		Tracing: config.TracingConfig{Enabled: true},
	}); err == nil {
		t.Fatal("Prepare succeeded with a failing exporter")
	}
	if !candidateWriter.closed.Load() {
		t.Fatal("candidate writer was not closed after tracing init failed")
	}
	if oldWriter.closed.Load() {
		t.Fatal("live writer was closed by failed preparation")
	}
	controller.Logging.Logger().Info("still live")
	if got := oldWriter.String(); !bytes.Contains([]byte(got), []byte(`"msg":"still live"`)) {
		t.Fatalf("old writer did not remain active: %q", got)
	}
}

func TestTracingHandleDrainsRequestBeforeExporterShutdown(t *testing.T) {
	oldExporter := &fakeExporter{}
	newExporter := &fakeExporter{}
	var builds atomic.Int64
	factory := func(context.Context, config.TracingConfig) (sdktrace.SpanExporter, error) {
		if builds.Add(1) == 1 {
			return oldExporter, nil
		}
		return newExporter, nil
	}
	handle, err := newTracingHandle(
		context.Background(),
		config.TracingConfig{Enabled: true},
		"old",
		factory,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = handle.Close(context.Background()) })

	started := make(chan struct{})
	release := make(chan struct{})
	handler := NewTracingMiddlewareWithHandle(handle, "route", "backend")(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			close(started)
			<-release
			w.WriteHeader(http.StatusNoContent)
		}),
	)
	requestDone := make(chan struct{})
	go func() {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
		close(requestDone)
	}()
	<-started

	next, err := handle.prepare(context.Background(), config.TracingConfig{Enabled: true}, "new")
	if err != nil {
		t.Fatal(err)
	}
	old := handle.swap(next)
	closeDone := make(chan error, 1)
	go func() { closeDone <- old.closeDrained(context.Background()) }()
	select {
	case <-closeDone:
		t.Fatal("old exporter shut down before its request span ended")
	case <-time.After(20 * time.Millisecond):
	}
	if oldExporter.shutdown.Load() {
		t.Fatal("old exporter was shut down while request was active")
	}
	close(release)
	<-requestDone
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	if !oldExporter.shutdown.Load() {
		t.Fatal("old exporter was not shut down after request drained")
	}
}
