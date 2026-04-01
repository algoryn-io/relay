package observability

import (
	"fmt"
	"io"
	"os"
	"sync"
)

type rotatingFileWriter struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	file     *os.File
	size     int64
}

var _ io.WriteCloser = (*rotatingFileWriter)(nil)

func newRotatingFileWriter(path string, maxBytes int64) (*rotatingFileWriter, error) {
	if path == "" {
		return nil, fmt.Errorf("log file path is required")
	}
	if maxBytes <= 0 {
		return nil, fmt.Errorf("max bytes must be greater than 0")
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}

	return &rotatingFileWriter{
		path:     path,
		maxBytes: maxBytes,
		file:     f,
		size:     info.Size(),
	}, nil
}

func (w *rotatingFileWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		return 0, fmt.Errorf("writer is closed")
	}
	if w.size+int64(len(p)) > w.maxBytes {
		if err := w.rotateLocked(); err != nil {
			return 0, err
		}
	}

	n, err := w.file.Write(p)
	w.size += int64(n)
	return n, err
}

func (w *rotatingFileWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	w.size = 0
	return err
}

func (w *rotatingFileWriter) rotateLocked() error {
	if err := w.file.Close(); err != nil {
		return err
	}

	backup := w.path + ".1"
	if err := os.Remove(backup); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(w.path, backup); err != nil && !os.IsNotExist(err) {
		return err
	}

	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	w.file = f
	w.size = 0
	return nil
}
