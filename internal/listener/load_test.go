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

// TestLoadSmoke drives the full server (real TCP socket, full middleware chain
// and proxy path) under concurrent load for a short burst. It is a regression
// guard: it asserts the gateway serves a healthy request rate with zero errors
// and that in-flight accounting returns to zero. Skipped under -short.
//
// Tune with env: not needed for CI; defaults keep it ~2s.
func TestLoadSmoke(t *testing.T) {
	if testing.Short() {
		t.Skip("load smoke skipped in -short mode")
	}

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(backend.Close)

	rt := &config.RuntimeConfig{
		Routes: map[string]config.RouteRuntime{
			"r": {Name: "r", Path: "/x", Methods: []string{http.MethodGet}, BackendName: "b"},
		},
		Backends: map[string]config.BackendRuntime{
			"b": {Name: "b", Strategy: "round_robin", Instances: []config.InstanceRuntime{{URL: backend.URL}}},
		},
	}
	server, err := New(testServerConfig(config.ListenerConfig{
		HTTP:     config.HTTPConfig{Port: 8080},
		Timeouts: config.TimeoutsConfig{Read: 5 * time.Second, Write: 5 * time.Second, Idle: 30 * time.Second},
	}), rt, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = server.Shutdown(context.Background()) })

	ts := httptest.NewServer(server)
	t.Cleanup(ts.Close)

	const (
		workers  = 50
		duration = 2 * time.Second
	)
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{MaxIdleConns: 200, MaxIdleConnsPerHost: 200},
	}
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()

	var ok, bad atomic.Int64
	var wg sync.WaitGroup
	start := time.Now()
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/x", nil)
				resp, err := client.Do(req)
				if err != nil {
					if ctx.Err() == nil {
						bad.Add(1)
					}
					continue
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					ok.Add(1)
				} else {
					bad.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	rps := float64(ok.Load()) / elapsed.Seconds()
	t.Logf("load smoke: %d ok, %d errors, %.0f req/s over %s (%d workers)",
		ok.Load(), bad.Load(), rps, elapsed.Round(time.Millisecond), workers)

	if bad.Load() != 0 {
		t.Fatalf("expected 0 errors under load, got %d", bad.Load())
	}
	if ok.Load() == 0 {
		t.Fatal("no successful requests under load")
	}
	// In-flight accounting must settle back to zero once load stops.
	if n := server.inFlight.Load(); n != 0 {
		t.Errorf("inFlight = %d after load, want 0", n)
	}
}
