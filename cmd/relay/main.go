package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"algoryn.io/relay/internal/config"
	"algoryn.io/relay/internal/listener"
)

const defaultConfig = "config/example.yaml"

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	configPath := os.Getenv("RELAY_CONFIG")
	if configPath == "" {
		configPath = defaultConfig
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		logger.Error("failed to load config", "path", configPath, "error", err)
		os.Exit(1)
	}

	if err := cfg.ResolveEnv(os.Getenv); err != nil {
		logger.Error("failed to resolve environment", "error", err)
		os.Exit(1)
	}

	if err := cfg.Validate(); err != nil {
		logger.Error("invalid config", "error", err)
		os.Exit(1)
	}

	rt, err := config.BuildRuntime(cfg)
	if err != nil {
		logger.Error("failed to build runtime config", "error", err)
		os.Exit(1)
	}

	server, err := listener.New(cfg.Listener, rt, logger)
	if err != nil {
		logger.Error("failed to create server", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		logger.Info("relay starting", "http_port", cfg.Listener.HTTP.Port)
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
