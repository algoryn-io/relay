package observability

import (
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"algoryn.io/relay/internal/config"
	"gopkg.in/natefinch/lumberjack.v2"
)

type Logger struct {
	logger      *slog.Logger
	accessWrite *lumberjack.Logger
	errorWrite  *lumberjack.Logger
}

type AccessLogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Method    string    `json:"method"`
	Path      string    `json:"path"`
	Status    int       `json:"status"`
	LatencyMs int64     `json:"latency_ms"`
	BackendID string    `json:"backend_id"`
	ClientIP  string    `json:"client_ip"`
	RouteID   string    `json:"route_id"`
}

type ErrorLogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Severity  string    `json:"severity"`
	Message   string    `json:"message"`
	Path      string    `json:"path"`
	Method    string    `json:"method"`
	RouteID   string    `json:"route_id"`
	BackendID string    `json:"backend_id"`
	Error     string    `json:"error"`
}

func New(cfg config.LogsConfig) *Logger {
	dir := cfg.Directory
	if dir == "" {
		dir = "."
	}
	_ = os.MkdirAll(dir, 0o755)

	access := &lumberjack.Logger{
		Filename:   filepath.Join(dir, "access.log"),
		MaxSize:    cfg.MaxSizeMB,
		MaxBackups: cfg.MaxBackups,
		MaxAge:     cfg.MaxAgeDays,
		Compress:   cfg.Compress,
	}
	errw := &lumberjack.Logger{
		Filename:   filepath.Join(dir, "error.log"),
		MaxSize:    cfg.MaxSizeMB,
		MaxBackups: cfg.MaxBackups,
		MaxAge:     cfg.MaxAgeDays,
		Compress:   cfg.Compress,
	}

	return &Logger{
		logger:      slog.New(slog.NewJSONHandler(os.Stdout, nil)),
		accessWrite: access,
		errorWrite:  errw,
	}
}

func (l *Logger) Slog() *slog.Logger {
	if l == nil || l.logger == nil {
		return slog.Default()
	}
	return l.logger
}

func (l *Logger) LogRequest(entry AccessLogEntry) {
	_ = entry
	// TODO: implement JSON access log marshaling and write rotation using lumberjack access writer.
	l.logger.Info("request logged", "path", entry.Path, "status", entry.Status)
}

func (l *Logger) LogError(entry ErrorLogEntry) {
	_ = entry
	// TODO: implement structured error log marshaling and write rotation using lumberjack error writer.
	l.logger.Error("error logged", "message", entry.Message, "error", entry.Error)
}
