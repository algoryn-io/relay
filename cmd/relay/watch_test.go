package main

import (
	"context"
	"log/slog"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestWatchConfigTriggersReload(t *testing.T) {
	t.Parallel()

	f, err := os.CreateTemp(t.TempDir(), "relay-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	_, _ = f.WriteString("version: 1\n")
	f.Close()

	var reloads atomic.Int64
	debounce := 50 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	go watchConfig(ctx, path, debounce, slog.Default(), func() { reloads.Add(1) })

	// Give the watcher time to register before writing.
	time.Sleep(30 * time.Millisecond)

	if err := os.WriteFile(path, []byte("version: 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(debounce + 400*time.Millisecond)
	for time.Now().Before(deadline) {
		if reloads.Load() >= 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("reload not triggered within deadline (reloads=%d)", reloads.Load())
}

func TestWatchConfigDebouncesRapidWrites(t *testing.T) {
	t.Parallel()

	f, err := os.CreateTemp(t.TempDir(), "relay-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	f.Close()

	var reloads atomic.Int64
	debounce := 100 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	go watchConfig(ctx, path, debounce, slog.Default(), func() { reloads.Add(1) })

	time.Sleep(30 * time.Millisecond)

	// 5 rapid writes within the debounce window — should collapse to 1 reload.
	for range 5 {
		_ = os.WriteFile(path, []byte("v\n"), 0o644)
		time.Sleep(15 * time.Millisecond)
	}

	time.Sleep(debounce + 300*time.Millisecond)

	got := reloads.Load()
	if got == 0 {
		t.Fatal("expected at least 1 reload, got 0")
	}
	if got > 2 {
		t.Fatalf("expected debounce to collapse rapid writes, got %d reloads", got)
	}
}

func TestWatchConfigCancellation(t *testing.T) {
	t.Parallel()

	f, err := os.CreateTemp(t.TempDir(), "relay-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	f.Close()

	var reloads atomic.Int64
	debounce := 50 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		watchConfig(ctx, path, debounce, slog.Default(), func() { reloads.Add(1) })
		close(done)
	}()

	time.Sleep(30 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("watchConfig did not exit after context cancellation")
	}
}
