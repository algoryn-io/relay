package observability

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type rotatingFileWriter struct {
	mu         sync.Mutex
	path       string
	maxBytes   int64
	maxAgeDays int
	compress   bool
	file       *os.File
	size       int64
	stop       chan struct{}
}

var _ io.WriteCloser = (*rotatingFileWriter)(nil)

func newRotatingFileWriter(path string, maxBytes int64, maxAgeDays int, compress bool) (*rotatingFileWriter, error) {
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

	w := &rotatingFileWriter{
		path:       path,
		maxBytes:   maxBytes,
		maxAgeDays: maxAgeDays,
		compress:   compress,
		file:       f,
		size:       info.Size(),
		stop:       make(chan struct{}),
	}

	if maxAgeDays > 0 {
		go w.runDailyRotation()
	}

	return w, nil
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
	close(w.stop)
	err := w.file.Close()
	w.file = nil
	w.size = 0
	return err
}

// rotateLocked renames the current log file to a timestamped backup, opens a new
// file, and optionally compresses the backup and purges old files.
// Must be called with w.mu held.
func (w *rotatingFileWriter) rotateLocked() error {
	if err := w.file.Close(); err != nil {
		return err
	}

	stamp := time.Now().Format("20060102-150405")
	backup := fmt.Sprintf("%s.%s", w.path, stamp)

	if err := os.Rename(w.path, backup); err != nil && !os.IsNotExist(err) {
		return err
	}

	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	w.file = f
	w.size = 0

	// Post-rotation work runs outside the lock to avoid holding it during I/O.
	go func() {
		if w.compress {
			_ = compressFile(backup)
		}
		if w.maxAgeDays > 0 {
			_ = purgeOldBackups(w.path, w.maxAgeDays)
		}
	}()

	return nil
}

// runDailyRotation fires at the next midnight and then every 24h, rotating the
// log so that age-based pruning is applied even when the file never hits maxBytes.
func (w *rotatingFileWriter) runDailyRotation() {
	for {
		now := time.Now()
		next := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, now.Location())
		select {
		case <-time.After(time.Until(next)):
			w.mu.Lock()
			if w.file != nil {
				_ = w.rotateLocked()
			}
			w.mu.Unlock()
		case <-w.stop:
			return
		}
	}
}

// compressFile gzips src to src+".gz" and removes the original.
// Writes to a temp file first and renames atomically so the .gz file
// only becomes visible once it is fully written.
func compressFile(src string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	dst := src + ".gz"
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}

	gz := gzip.NewWriter(out)
	if _, err := io.Copy(gz, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := gz.Close(); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	in.Close()

	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Remove(src)
}

// purgeOldBackups deletes timestamped backups of logPath older than maxAgeDays days.
// It matches files named <base>.<timestamp>[.gz] in the same directory.
func purgeOldBackups(logPath string, maxAgeDays int) error {
	dir := filepath.Dir(logPath)
	base := filepath.Base(logPath)
	cutoff := time.Now().AddDate(0, 0, -maxAgeDays)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, base+".") || name == base {
			continue
		}
		// Strip base prefix and optional .gz suffix to isolate the timestamp.
		rest := strings.TrimPrefix(name, base+".")
		rest = strings.TrimSuffix(rest, ".gz")

		t, err := time.ParseInLocation("20060102-150405", rest, time.Local)
		if err != nil {
			continue // not a file we created — skip
		}
		if t.Before(cutoff) {
			_ = os.Remove(filepath.Join(dir, name))
		}
	}
	return nil
}
