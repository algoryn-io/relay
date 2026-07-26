package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
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

	cfg, configFiles, err := config.LoadWithFiles(configPath)
	if err != nil {
		bootstrapLogger.Error("failed to load config", "path", configPath, "error", err)
		os.Exit(1)
	}

	if err := cfg.ResolveEnv(os.Getenv); err != nil {
		bootstrapLogger.Error("failed to resolve environment", "error", err)
		os.Exit(1)
	}

	if err := cfg.ResolveSecretFiles(nil); err != nil {
		bootstrapLogger.Error("failed to resolve secret files", "error", err)
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
	startupHTTPPort := cfg.Listener.HTTP.Port

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var (
		configMu sync.RWMutex
		reloadMu sync.Mutex
	)
	currentDebounce := func() time.Duration {
		configMu.RLock()
		defer configMu.RUnlock()
		return cfg.Reload.Debounce
	}

	// reload loads, validates, and applies a new config version atomically.
	// On success it updates cfg so subsequent reloads read the latest debounce value.
	reload := func() watchReloadResult {
		reloadMu.Lock()
		defer reloadMu.Unlock()

		newCfg, files, loadErr := config.LoadWithFiles(configPath)
		result := watchReloadResult{files: files, debounce: currentDebounce()}
		if loadErr != nil {
			logger.Error("reload failed: load", "error", loadErr)
			return result
		}
		if loadErr = newCfg.ResolveEnv(os.Getenv); loadErr != nil {
			logger.Error("reload failed: resolve env", "error", loadErr)
			return result
		}
		if loadErr = newCfg.ResolveSecretFiles(nil); loadErr != nil {
			logger.Error("reload failed: resolve secret files", "error", loadErr)
			return result
		}
		if loadErr = newCfg.Validate(); loadErr != nil {
			logger.Error("reload failed: invalid config", "error", loadErr)
			return result
		}
		newRt, loadErr := config.BuildRuntime(newCfg)
		if loadErr != nil {
			logger.Error("reload failed: build runtime", "error", loadErr)
			return result
		}
		if loadErr = server.Reload(newCfg, newRt); loadErr != nil {
			logger.Error("reload failed: apply", "error", loadErr)
			return result
		}
		configMu.Lock()
		cfg = newCfg
		configMu.Unlock()
		result.success = true
		result.debounce = newCfg.Reload.Debounce
		logger.Info("config reloaded", "path", configPath)
		return result
	}

	var supervisor *configWatchSupervisor
	if cfg.Reload.Watch {
		supervisor, err = newConfigWatchSupervisor(
			configFiles,
			cfg.Reload.Debounce,
			logger,
			func() watchReloadResult {
				logger.Info("reloading config (file change)", "path", configPath)
				return reload()
			},
		)
		if err != nil {
			logger.Error("file watcher: failed to initialize", "error", err)
		} else {
			go supervisor.run(ctx)
		}
	}

	// SIGHUP: manual hot reload trigger.
	sigHUP := make(chan os.Signal, 1)
	signal.Notify(sigHUP, syscall.SIGHUP)
	defer signal.Stop(sigHUP)
	go func() {
		var lastReload time.Time
		for {
			select {
			case <-ctx.Done():
				return
			case <-sigHUP:
				debounce := currentDebounce()
				if debounce > 0 && time.Since(lastReload) < debounce {
					logger.Info("reload debounced", "debounce", debounce)
					continue
				}
				logger.Info("reloading config (SIGHUP)", "path", configPath)
				result := reload()
				if supervisor != nil {
					supervisor.update(ctx, result)
				}
				lastReload = time.Now()
			}
		}
	}()

	errCh := make(chan error, 1)
	go func() {
		logger.Info("relay starting",
			"http_port", startupHTTPPort,
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
