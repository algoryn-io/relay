package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"algoryn.io/relay/internal/config"
	"algoryn.io/relay/internal/listener"
	"algoryn.io/relay/internal/observability"
)

var (
	version   = "dev"
	buildTime = "unknown"
)

const defaultConfig = "config/example.yaml"

func main() {
	var (
		configFlag   string
		validateFlag bool
		versionFlag  bool
	)
	flag.StringVar(&configFlag, "config", "", "path to config file (overrides RELAY_CONFIG)")
	flag.BoolVar(&validateFlag, "validate", false, "validate config and exit")
	flag.BoolVar(&versionFlag, "version", false, "print version and exit")
	flag.Parse()

	if versionFlag {
		fmt.Printf("relay %s (built %s)\n", version, buildTime)
		return
	}

	bootstrapLogger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	configPath := configFlag
	if configPath == "" {
		configPath = os.Getenv("RELAY_CONFIG")
	}
	if configPath == "" {
		configPath = defaultConfig
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		bootstrapLogger.Error("failed to load config", "path", configPath, "error", err)
		os.Exit(1)
	}

	if err := cfg.ResolveEnv(os.Getenv); err != nil {
		bootstrapLogger.Error("failed to resolve environment", "error", err)
		os.Exit(1)
	}

	if err := cfg.Validate(); err != nil {
		bootstrapLogger.Error("invalid config", "error", err)
		os.Exit(1)
	}

	if validateFlag {
		bootstrapLogger.Info("config valid", "path", configPath)
		return
	}

	logger, logCloser, err := observability.NewAccessLogger(cfg.Observability.Logs)
	if err != nil {
		bootstrapLogger.Error("failed to initialize access logger", "error", err)
		os.Exit(1)
	}
	defer func() {
		if logCloser != nil {
			_ = logCloser.Close()
		}
	}()

	rt, err := config.BuildRuntime(cfg)
	if err != nil {
		logger.Error("failed to build runtime config", "error", err)
		os.Exit(1)
	}

	server, err := listener.New(cfg, rt, logger)
	if err != nil {
		logger.Error("failed to create server", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// SIGHUP triggers a hot reload: config is re-read, validated, and applied
	// without interrupting in-flight requests or closing the TCP listener.
	sigHUP := make(chan os.Signal, 1)
	signal.Notify(sigHUP, syscall.SIGHUP)
	go func() {
		var lastReload time.Time
		for {
			select {
			case <-ctx.Done():
				return
			case <-sigHUP:
				debounce := cfg.Reload.Debounce
				if debounce > 0 && time.Since(lastReload) < debounce {
					logger.Info("reload debounced", "debounce", debounce)
					continue
				}
				logger.Info("reloading config", "path", configPath)
				newCfg, loadErr := config.Load(configPath)
				if loadErr != nil {
					logger.Error("reload failed: load", "error", loadErr)
					continue
				}
				if loadErr = newCfg.ResolveEnv(os.Getenv); loadErr != nil {
					logger.Error("reload failed: resolve env", "error", loadErr)
					continue
				}
				if loadErr = newCfg.Validate(); loadErr != nil {
					logger.Error("reload failed: invalid config", "error", loadErr)
					continue
				}
				newRt, loadErr := config.BuildRuntime(newCfg)
				if loadErr != nil {
					logger.Error("reload failed: build runtime", "error", loadErr)
					continue
				}
				if loadErr = server.Reload(newCfg, newRt); loadErr != nil {
					logger.Error("reload failed: apply", "error", loadErr)
					continue
				}
				cfg = newCfg
				lastReload = time.Now()
				logger.Info("config reloaded", "path", configPath)
			}
		}
	}()

	errCh := make(chan error, 1)
	go func() {
		logger.Info("relay starting",
			"http_port", cfg.Listener.HTTP.Port,
			"version", version,
			"built", buildTime,
		)
		errCh <- server.Start()
	}()

	select {
	case <-ctx.Done():
	case err := <-errCh:
		if err != nil {
			logger.Error("server stopped", "error", err)
			os.Exit(1)
		}
		return
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
		os.Exit(1)
	}
}
