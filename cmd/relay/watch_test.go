package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"algoryn.io/relay/internal/config"
)

func TestConfigWatchSupervisorWatchesTransitiveFileAndAtomicSave(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	root := filepath.Join(dir, "relay.yaml")
	include := filepath.Join(dir, "routes.yaml")
	writeTestFile(t, root, "include: [routes.yaml]\n")
	writeTestFile(t, include, "routes: []\n")

	reloaded := make(chan struct{}, 1)
	s := newTestSupervisor(t, []string{root, include}, 20*time.Millisecond, func() watchReloadResult {
		return watchReloadResult{
			files:    []string{root, include},
			debounce: 20 * time.Millisecond,
			success:  true,
		}
	}, reloaded)

	tmp := filepath.Join(dir, ".routes.yaml.tmp")
	writeTestFile(t, tmp, "routes:\n  - name: replaced\n")
	if err := os.Rename(tmp, include); err != nil {
		t.Fatal(err)
	}
	waitSignal(t, reloaded, "atomic include replacement")
	stopTestSupervisor(t, s)
}

func TestConfigWatchSupervisorUpdatesFilesAndDebounce(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	root := filepath.Join(dir, "relay.yaml")
	oldInclude := filepath.Join(dir, "old.yaml")
	newInclude := filepath.Join(dir, "new.yaml")
	for _, path := range []string{root, oldInclude, newInclude} {
		writeTestFile(t, path, "routes: []\n")
	}

	var calls atomic.Int64
	reloaded := make(chan struct{}, 4)
	s := newTestSupervisor(t, []string{root, oldInclude}, 80*time.Millisecond, func() watchReloadResult {
		calls.Add(1)
		return watchReloadResult{
			files:    []string{root, newInclude},
			debounce: 10 * time.Millisecond,
			success:  true,
		}
	}, reloaded)

	writeTestFile(t, root, "include: [new.yaml]\n")
	waitSignal(t, reloaded, "root reload")

	writeTestFile(t, oldInclude, "routes: [old]\n")
	assertNoSignal(t, reloaded, 150*time.Millisecond, "removed include")

	writeTestFile(t, newInclude, "routes: [new]\n")
	waitSignal(t, reloaded, "new include")
	if got := calls.Load(); got != 2 {
		t.Fatalf("reload calls = %d, want 2", got)
	}
	stopTestSupervisor(t, s)
}

func TestConfigWatchSupervisorAppliesReloadedDebounce(t *testing.T) {
	t.Parallel()

	root := filepath.Join(t.TempDir(), "relay.yaml")
	writeTestFile(t, root, "routes: []\n")
	s, err := newConfigWatchSupervisor(
		[]string{root},
		80*time.Millisecond,
		slog.Default(),
		func() watchReloadResult { return watchReloadResult{} },
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.watcher.Close() })

	s.apply(watchReloadResult{
		files:    []string{root},
		debounce: 10 * time.Millisecond,
		success:  true,
	})
	if s.debounce != 10*time.Millisecond {
		t.Fatalf("debounce = %v, want 10ms", s.debounce)
	}
}

func TestConfigWatchSupervisorRecoversWhenMissingIncludeAppears(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	root := filepath.Join(dir, "relay.yaml")
	stable := filepath.Join(dir, "stable.yaml")
	missing := filepath.Join(dir, "generated", "routes.yaml")
	writeTestFile(t, root, "include: [stable.yaml]\n")
	writeTestFile(t, stable, "routes: []\n")

	reloaded := make(chan struct{}, 8)
	success := make(chan struct{}, 1)
	callback := func() watchReloadResult {
		_, files, err := config.LoadWithFiles(root)
		result := watchReloadResult{
			files:    files,
			debounce: 20 * time.Millisecond,
			success:  err == nil,
		}
		if err == nil {
			select {
			case success <- struct{}{}:
			default:
			}
		}
		return result
	}
	s := newTestSupervisor(t, []string{root, stable}, 20*time.Millisecond, callback, reloaded)

	writeTestFile(t, root, "include: [generated/routes.yaml]\n")
	waitSignal(t, reloaded, "failed reload with missing include")
	assertNoSignal(t, success, 50*time.Millisecond, "missing include success")

	if err := os.MkdirAll(filepath.Dir(missing), 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, missing, "routes: []\n")
	waitSignal(t, success, "missing include recovery")
	stopTestSupervisor(t, s)
}

func TestConfigWatchSupervisorDebouncesAndCloses(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	root := filepath.Join(dir, "relay.yaml")
	writeTestFile(t, root, "routes: []\n")

	var calls atomic.Int64
	reloaded := make(chan struct{}, 5)
	ctx, cancel := context.WithCancel(context.Background())
	s, err := newConfigWatchSupervisor([]string{root}, 60*time.Millisecond, slog.Default(), func() watchReloadResult {
		calls.Add(1)
		select {
		case reloaded <- struct{}{}:
		default:
		}
		return watchReloadResult{files: []string{root}, debounce: 60 * time.Millisecond, success: true}
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		s.run(ctx)
		close(done)
	}()

	for i := range 5 {
		writeTestFile(t, root, "routes: []\n# "+string(rune('a'+i))+"\n")
		time.Sleep(8 * time.Millisecond)
	}
	waitSignal(t, reloaded, "debounced reload")
	time.Sleep(100 * time.Millisecond)
	if got := calls.Load(); got != 1 {
		t.Fatalf("reload calls = %d, want 1", got)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("supervisor did not close after cancellation")
	}
}

func newTestSupervisor(
	t *testing.T,
	files []string,
	debounce time.Duration,
	callback func() watchReloadResult,
	reloaded chan<- struct{},
) *runningTestSupervisor {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	wrapped := func() watchReloadResult {
		result := callback()
		select {
		case reloaded <- struct{}{}:
		default:
		}
		return result
	}
	supervisor, err := newConfigWatchSupervisor(files, debounce, slog.Default(), wrapped)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		supervisor.run(ctx)
		close(done)
	}()
	return &runningTestSupervisor{supervisor: supervisor, cancel: cancel, done: done}
}

type runningTestSupervisor struct {
	supervisor *configWatchSupervisor
	cancel     context.CancelFunc
	done       <-chan struct{}
}

func stopTestSupervisor(t *testing.T, running *runningTestSupervisor) {
	t.Helper()
	running.cancel()
	select {
	case <-running.done:
	case <-time.After(time.Second):
		t.Fatal("supervisor did not close")
	}
}

func writeTestFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func waitSignal(t *testing.T, ch <-chan struct{}, operation string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", operation)
	}
}

func assertNoSignal(t *testing.T, ch <-chan struct{}, wait time.Duration, operation string) {
	t.Helper()
	select {
	case <-ch:
		t.Fatalf("unexpected signal for %s", operation)
	case <-time.After(wait):
	}
}
