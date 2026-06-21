package observability

import (
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"algoryn.io/relay/internal/config"
)

func TestRotatingFileWriterCreatesAndWritesFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "access.log")
	w, err := newRotatingFileWriter(path, 64, 0, false)
	if err != nil {
		t.Fatalf("newRotatingFileWriter() error = %v", err)
	}
	defer w.Close()

	if _, err := w.Write([]byte("hello")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(data) != "hello" {
		t.Fatalf("file content = %q, want hello", string(data))
	}
}

func TestRotatingFileWriterRotatesOnSizeExceeded(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	w, err := newRotatingFileWriter(path, 10, 0, false)
	if err != nil {
		t.Fatalf("newRotatingFileWriter() error = %v", err)
	}
	defer w.Close()

	if _, err := w.Write([]byte("123456789")); err != nil {
		t.Fatalf("first Write() error = %v", err)
	}
	// This write exceeds maxBytes → rotation happens before writing.
	if _, err := w.Write([]byte("abcd")); err != nil {
		t.Fatalf("second Write() error = %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// Current file must contain only the post-rotation content.
	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(current) error = %v", err)
	}
	if string(current) != "abcd" {
		t.Fatalf("current content = %q, want abcd", string(current))
	}

	// One timestamped backup must exist.
	backups := findBackups(t, dir, "access.log")
	if len(backups) != 1 {
		t.Fatalf("expected 1 backup, found %d: %v", len(backups), backups)
	}

	backupData, err := os.ReadFile(filepath.Join(dir, backups[0]))
	if err != nil {
		t.Fatalf("ReadFile(backup) error = %v", err)
	}
	if string(backupData) != "123456789" {
		t.Fatalf("backup content = %q, want 123456789", string(backupData))
	}
}

func TestRotatingFileWriterCompressesBackup(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	w, err := newRotatingFileWriter(path, 5, 0, true /* compress */)
	if err != nil {
		t.Fatalf("newRotatingFileWriter() error = %v", err)
	}
	defer w.Close()

	if _, err := w.Write([]byte("hello")); err != nil {
		t.Fatalf("first Write() error = %v", err)
	}
	if _, err := w.Write([]byte("world")); err != nil {
		t.Fatalf("second Write() error = %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// Wait for the async compress goroutine.
	deadline := time.Now().Add(2 * time.Second)
	var gzFiles []string
	for time.Now().Before(deadline) {
		gzFiles = findBackupsWithSuffix(t, dir, "access.log", ".gz")
		if len(gzFiles) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(gzFiles) == 0 {
		t.Fatal("expected .gz backup, none found")
	}

	// Verify it's a valid gzip file containing the original content.
	f, err := os.Open(filepath.Join(dir, gzFiles[0]))
	if err != nil {
		t.Fatalf("os.Open(.gz) error = %v", err)
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip.NewReader error = %v", err)
	}
	defer gr.Close()

	content, err := io.ReadAll(gr)
	if err != nil {
		t.Fatalf("read gzip content error = %v", err)
	}
	if string(content) != "hello" {
		t.Fatalf("gzip content = %q, want hello", string(content))
	}
}

func TestRotatingFileWriterPurgesOldBackups(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")

	// Create two stale backups with timestamps in the past.
	stale1 := path + ".20200101-120000"
	stale2 := path + ".20190615-080000"
	for _, f := range []string{stale1, stale2} {
		if err := os.WriteFile(f, []byte("old"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	w, err := newRotatingFileWriter(path, 5, 1 /* maxAgeDays=1 */, false)
	if err != nil {
		t.Fatalf("newRotatingFileWriter() error = %v", err)
	}
	defer w.Close()

	// Trigger a rotation.
	if _, err := w.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("world")); err != nil {
		t.Fatal(err)
	}

	// Wait for the async purge goroutine.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(stale1); os.IsNotExist(err) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if _, err := os.Stat(stale1); !os.IsNotExist(err) {
		t.Errorf("stale backup %s was not purged", stale1)
	}
	if _, err := os.Stat(stale2); !os.IsNotExist(err) {
		t.Errorf("stale backup %s was not purged", stale2)
	}
}

func TestNewAccessLoggerWritesToFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "access.log")
	logger, closer, err := NewAccessLogger(config.LogsConfig{
		Level:     "info",
		Format:    "json",
		File:      path,
		MaxSizeMB: 1,
	})
	if err != nil {
		t.Fatalf("NewAccessLogger() error = %v", err)
	}
	defer func() {
		if closer != nil {
			_ = closer.Close()
		}
	}()

	logger.Info("request", "method", "GET", "path", "/api/orders", "status", 200)
	if err := closer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !strings.Contains(string(data), `"msg":"request"`) {
		t.Fatalf("log file does not contain request message: %q", string(data))
	}
}

func TestNewAccessLoggerToStdout(t *testing.T) {
	t.Parallel()

	logger, closer, err := NewAccessLogger(config.LogsConfig{Level: "info"})
	if err != nil {
		t.Fatalf("NewAccessLogger() stdout error = %v", err)
	}
	defer closer.Close()
	logger.Info("ping")
}

// ── helpers ───────────────────────────────────────────────────────────────────

func findBackups(t *testing.T, dir, base string) []string {
	t.Helper()
	return findBackupsWithSuffix(t, dir, base, "")
}

func findBackupsWithSuffix(t *testing.T, dir, base, suffix string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if name == base {
			continue
		}
		if strings.HasPrefix(name, base+".") && strings.HasSuffix(name, suffix) {
			out = append(out, name)
		}
	}
	return out
}
