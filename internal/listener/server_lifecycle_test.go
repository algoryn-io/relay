package listener

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"algoryn.io/relay/internal/config"
)

func TestReloadDrainsInFlightRequestBeforeClosingOldState(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	v1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		_, _ = w.Write([]byte("v1"))
	}))
	t.Cleanup(v1.Close)
	v2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("v2"))
	}))
	t.Cleanup(v2.Close)

	cfg := lifecycleConfig()
	server, err := New(cfg, lifecycleRuntime(v1.URL), discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Shutdown(context.Background()) })
	old := server.state.Load()

	requestDone := make(chan string, 1)
	go func() {
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/svc", nil))
		requestDone <- rec.Body.String()
	}()
	<-started

	if err := server.Reload(cfg, lifecycleRuntime(v2.URL)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-old.done:
		t.Fatal("old state closed while its request was in flight")
	default:
	}

	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/svc", nil))
	if got := rec.Body.String(); got != "v2" {
		t.Fatalf("new request body = %q, want v2", got)
	}

	close(release)
	if got := <-requestDone; got != "v1" {
		t.Fatalf("in-flight request body = %q, want v1", got)
	}
	select {
	case <-old.done:
	case <-time.After(time.Second):
		t.Fatal("old state was not closed after its request drained")
	}
}

func TestBuildStateFailureClosesPartialProxy(t *testing.T) {
	var probes atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		probes.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	rt := lifecycleRuntime(upstream.URL)
	backend := rt.Backends["svc-backend"]
	backend.HealthCheck = config.HealthCheckConfig{
		Path:     "/health",
		Interval: 5 * time.Millisecond,
		Timeout:  time.Second,
	}
	rt.Backends["svc-backend"] = backend
	route := rt.Routes["svc"]
	route.MiddlewareRefs = []string{"missing"}
	rt.Routes["svc"] = route
	rt.Middleware = map[string]config.MiddlewareRuntime{
		"limiter": {
			Name: "limiter",
			Type: "rate_limit",
			Config: config.MiddlewareSettingsConfig{
				Limit:                 10,
				Window:                time.Second,
				MemoryMaxBuckets:      10,
				MemoryBucketTTL:       time.Second,
				MemoryCleanupInterval: 5 * time.Millisecond,
			},
		},
	}

	if _, err := buildState(lifecycleConfig(), rt, discardLogger()); err == nil {
		t.Fatal("buildState() succeeded with an unresolved middleware")
	}
	time.Sleep(20 * time.Millisecond)
	afterClose := probes.Load()
	time.Sleep(30 * time.Millisecond)
	if got := probes.Load(); got != afterClose {
		t.Fatalf("health loop survived failed build: probes increased from %d to %d", afterClose, got)
	}
}

func TestRepeatedReloadClosesEveryRetiredState(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)

	cfg := lifecycleConfig()
	server, err := New(cfg, lifecycleRuntime(upstream.URL), discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Shutdown(context.Background()) })

	var retired []*serverState
	for range 25 {
		retired = append(retired, server.state.Load())
		if err := server.Reload(cfg, lifecycleRuntime(upstream.URL)); err != nil {
			t.Fatal(err)
		}
	}
	for i, st := range retired {
		select {
		case <-st.done:
		case <-time.After(time.Second):
			t.Fatalf("retired state %d did not close", i)
		}
	}

	server.lifecycleMu.Lock()
	stateCount := len(server.states)
	server.lifecycleMu.Unlock()
	if stateCount != 1 {
		t.Fatalf("tracked states = %d, want only current state", stateCount)
	}
}

func TestStateCloseIsIdempotentAndLeaseAware(t *testing.T) {
	var closes atomic.Int64
	owner := &resourceOwner{}
	owner.add(closerFunc(func() error {
		closes.Add(1)
		return nil
	}))
	st := &serverState{
		owner:   owner,
		drained: make(chan struct{}),
		done:    make(chan struct{}),
	}
	if !st.acquire() {
		t.Fatal("initial state lease rejected")
	}
	st.retire(time.Second)
	select {
	case <-st.done:
		t.Fatal("state closed before lease release")
	default:
	}
	st.release()
	<-st.done
	st.close()
	st.close()
	if got := closes.Load(); got != 1 {
		t.Fatalf("resource closed %d times, want 1", got)
	}
}

func TestStateRetireUsesBoundedDrainTimeout(t *testing.T) {
	var closes atomic.Int64
	owner := &resourceOwner{}
	owner.add(closerFunc(func() error {
		closes.Add(1)
		return nil
	}))
	st := &serverState{
		owner:   owner,
		drained: make(chan struct{}),
		done:    make(chan struct{}),
	}
	if !st.acquire() {
		t.Fatal("initial state lease rejected")
	}

	st.retire(20 * time.Millisecond)
	select {
	case <-st.done:
	case <-time.After(time.Second):
		t.Fatal("retired state exceeded its drain timeout")
	}
	st.release()
	if got := closes.Load(); got != 1 {
		t.Fatalf("resource closed %d times, want 1", got)
	}
}

func TestConcurrentReloadAndShutdown(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)
	cfg := lifecycleConfig()
	server, err := New(cfg, lifecycleRuntime(upstream.URL), discardLogger())
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range 20 {
			if err := server.Reload(cfg, lifecycleRuntime(upstream.URL)); err != nil {
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			t.Errorf("Shutdown() error = %v", err)
		}
	}()
	wg.Wait()

	if err := server.Reload(cfg, lifecycleRuntime(upstream.URL)); err == nil {
		t.Fatal("Reload() succeeded after shutdown")
	}
}

func lifecycleConfig() *config.Config {
	return testServerConfig(config.ListenerConfig{
		HTTP: config.HTTPConfig{Port: 8080},
		Timeouts: config.TimeoutsConfig{
			Read:  time.Second,
			Write: time.Second,
			Idle:  time.Second,
		},
	})
}

func lifecycleRuntime(upstream string) *config.RuntimeConfig {
	return &config.RuntimeConfig{
		Routes: map[string]config.RouteRuntime{
			"svc": {
				Name:        "svc",
				Path:        "/svc",
				Methods:     []string{http.MethodGet},
				BackendName: "svc-backend",
			},
		},
		Backends: map[string]config.BackendRuntime{
			"svc-backend": {
				Name:      "svc-backend",
				Instances: []config.InstanceRuntime{{URL: upstream}},
			},
		},
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
