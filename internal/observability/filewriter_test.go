package observability

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"algoryn.io/relay/internal/config"
)

func TestRotatingFileWriterCreatesAndWritesFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "access.log")
	w, err := newRotatingFileWriter(path, 64)
	if err != nil {
		t.Fatalf("newRotatingFileWriter() error = %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })

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

func TestRotatingFileWriterRotatesAndKeepsWriting(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "access.log")
	w, err := newRotatingFileWriter(path, 10)
	if err != nil {
		t.Fatalf("newRotatingFileWriter() error = %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })

	if _, err := w.Write([]byte("123456789")); err != nil {
		t.Fatalf("first Write() error = %v", err)
	}
	if _, err := w.Write([]byte("ab")); err != nil {
		t.Fatalf("second Write() error = %v", err)
	}
	if _, err := w.Write([]byte("cd")); err != nil {
		t.Fatalf("third Write() error = %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	backupData, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatalf("ReadFile(backup) error = %v", err)
	}
	if string(backupData) != "123456789" {
		t.Fatalf("backup content = %q, want 123456789", string(backupData))
	}

	currentData, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(current) error = %v", err)
	}
	if string(currentData) != "abcd" {
		t.Fatalf("current content = %q, want abcd", string(currentData))
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
	t.Cleanup(func() {
		if closer != nil {
			_ = closer.Close()
		}
	})

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
