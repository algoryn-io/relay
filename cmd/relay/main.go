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

	"github.com/fsnotify/fsnotify"

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

	tracingCtx := context.Background()
	fallbackSvc := cfg.Observability.Fabric.ServiceName
	shutdownTracing, err := observability.InitTracing(tracingCtx, cfg.Observability.Tracing, fallbackSvc)
	if err != nil {
		logger.Error("failed to initialize tracing", "error", err)
		os.Exit(1)
	}
	defer func() {
		flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := shutdownTracing(flushCtx); err != nil {
			logger.Warn("tracing shutdown error", "error", err)
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

	// reload loads, validates, and applies a new config version atomically.
	// On success it updates cfg so subsequent reloads read the latest debounce value.
	reload := func() {
		newCfg, loadErr := config.Load(configPath)
		if loadErr != nil {
			logger.Error("reload failed: load", "error", loadErr)
			return
		}
		if loadErr = newCfg.ResolveEnv(os.Getenv); loadErr != nil {
			logger.Error("reload failed: resolve env", "error", loadErr)
			return
		}
		if loadErr = newCfg.Validate(); loadErr != nil {
			logger.Error("reload failed: invalid config", "error", loadErr)
			return
		}
		newRt, loadErr := config.BuildRuntime(newCfg)
		if loadErr != nil {
			logger.Error("reload failed: build runtime", "error", loadErr)
			return
		}
		if loadErr = server.Reload(newCfg, newRt); loadErr != nil {
			logger.Error("reload failed: apply", "error", loadErr)
			return
		}
		cfg = newCfg
		logger.Info("config reloaded", "path", configPath)
	}

	// SIGHUP: manual hot reload trigger.
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
				logger.Info("reloading config (SIGHUP)", "path", configPath)
				reload()
				lastReload = time.Now()
			}
		}
	}()

	// File watch: automatic reload when the config file is written.
	if cfg.Reload.Watch {
		go watchConfig(ctx, configPath, cfg.Reload.Debounce, logger, func() {
			logger.Info("reloading config (file change)", "path", configPath)
			reload()
		})
	}

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

// watchConfig watches configPath for modifications and calls onReload after debounce.
// Handles atomic saves (rename + create) used by editors like vim/neovim by
// re-registering the watch after the inode changes.
func watchConfig(
	ctx context.Context,
	configPath string,
	debounce time.Duration,
	logger *slog.Logger,
	onReload func(),
) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		logger.Error("file watcher: failed to create", "error", err)
		return
	}
	defer watcher.Close()

	if err := watcher.Add(configPath); err != nil {
		logger.Error("file watcher: failed to watch config", "path", configPath, "error", err)
		return
	}
	logger.Info("file watcher: watching config", "path", configPath, "debounce", debounce)

	var debounceTimer *time.Timer

	scheduleReload := func() {
		if debounceTimer != nil {
			debounceTimer.Stop()
		}
		debounceTimer = time.AfterFunc(debounce, onReload)
	}

	for {
		select {
		case <-ctx.Done():
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			return

		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			switch {
			case event.Has(fsnotify.Write) || event.Has(fsnotify.Create):
				scheduleReload()
			case event.Has(fsnotify.Rename) || event.Has(fsnotify.Remove):
				// Atomic-save editors rename the temp file over the original,
				// causing fsnotify to lose the inode. Re-add the watch.
				_ = watcher.Remove(configPath)
				if addErr := watcher.Add(configPath); addErr == nil {
					scheduleReload()
				} else {
					logger.Warn("file watcher: lost watch after rename", "error", addErr)
				}
			}

		case watchErr, ok := <-watcher.Errors:
			if !ok {
				return
			}
			logger.Warn("file watcher error", "error", watchErr)
		}
	}
}
