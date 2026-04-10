package observability

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"algoryn.io/relay/internal/config"
)

const defaultLogMaxSizeMB = 10

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

func NewAccessLogger(cfg config.LogsConfig) (*slog.Logger, io.Closer, error) {
	level := parseLogLevel(cfg.Level)
	opts := &slog.HandlerOptions{Level: level}

	filePath := strings.TrimSpace(cfg.File)
	if filePath == "" {
		format := strings.ToLower(strings.TrimSpace(cfg.Format))
		if format == "text" {
			return slog.New(slog.NewTextHandler(os.Stdout, opts)), nopCloser{}, nil
		}
		return slog.New(slog.NewJSONHandler(os.Stdout, opts)), nopCloser{}, nil
	}

	maxSizeMB := cfg.MaxSizeMB
	if maxSizeMB <= 0 {
		maxSizeMB = defaultLogMaxSizeMB
	}

	if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
		return nil, nil, err
	}

	writer, err := newRotatingFileWriter(filePath, int64(maxSizeMB)*1024*1024)
	if err != nil {
		return nil, nil, err
	}

	return slog.New(slog.NewJSONHandler(writer, opts)), writer, nil
}

func parseLogLevel(level string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
