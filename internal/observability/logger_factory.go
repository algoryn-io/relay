package observability

import (
	"context"
	"errors"
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

type joinedCloser []io.Closer

func (c joinedCloser) Close() error {
	errs := make([]error, 0, len(c))
	for i := len(c) - 1; i >= 0; i-- {
		if c[i] != nil {
			errs = append(errs, c[i].Close())
		}
	}
	return errors.Join(errs...)
}

func NewAccessLogger(cfg config.LogsConfig) (*slog.Logger, io.Closer, error) {
	level := parseLogLevel(cfg.Level)
	opts := &slog.HandlerOptions{Level: level}
	newHandler := func(writer io.Writer) slog.Handler {
		if strings.EqualFold(strings.TrimSpace(cfg.Format), "text") {
			return slog.NewTextHandler(writer, opts)
		}
		return slog.NewJSONHandler(writer, opts)
	}

	filePath := strings.TrimSpace(cfg.File)
	var (
		localHandler slog.Handler
		localCloser  io.Closer = nopCloser{}
	)
	if filePath == "" {
		localHandler = newHandler(os.Stdout)
	} else {
		maxSizeMB := cfg.MaxSizeMB
		if maxSizeMB <= 0 {
			maxSizeMB = defaultLogMaxSizeMB
		}
		if err := os.MkdirAll(filepath.Dir(filePath), 0o750); err != nil {
			return nil, nil, err
		}
		writer, err := newRotatingFileWriter(filePath, int64(maxSizeMB)*1024*1024, cfg.MaxAgeDays, cfg.Compress)
		if err != nil {
			return nil, nil, err
		}
		async := newAsyncWriter(writer, asyncQueueSize)
		localHandler = newHandler(async)
		localCloser = async
	}

	if !cfg.OTLP.Enabled {
		return slog.New(localHandler), localCloser, nil
	}
	sink, err := newOTLPLogSink(context.Background(), cfg.OTLP)
	if err != nil {
		_ = localCloser.Close()
		return nil, nil, err
	}
	otlpHandler := &otlpSlogHandler{sink: sink, level: level}
	return slog.New(fanoutHandler{handlers: []slog.Handler{localHandler, otlpHandler}}),
		joinedCloser{localCloser, sink}, nil
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
