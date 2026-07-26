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
	configFiles = appendTLSWatchFiles(configFiles, cfg)

	if validateFlag {
		bootstrapLogger.Info("config valid", "path", configPath)
		return
	}

	observabilityController, err := observability.NewController(context.Background(), cfg.Observability)
	if err != nil {
		bootstrapLogger.Error("failed to initialize observability", "error", err)
		os.Exit(1)
	}
	logger := observabilityController.Logging.Logger()
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if closeErr := observabilityController.Close(closeCtx); closeErr != nil {
			bootstrapLogger.Warn("observability shutdown error", "error", closeErr)
		}
	}()

	rt, err := config.BuildRuntime(cfg)
	if err != nil {
		logger.Error("failed to build runtime config", "error", err)
		os.Exit(1)
	}

	server, err := listener.New(cfg, rt, logger, observabilityController.Tracing)
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
		result := watchReloadResult{files: appendTLSWatchFiles(files, newCfg), debounce: currentDebounce()}
		fail := func(stage string, reloadErr error) watchReloadResult {
			server.RecordConfigReload("failure", stage)
			logger.Error("config reload failed", "stage", stage, "error", reloadErr)
			return result
		}
		if loadErr != nil {
			return fail("load", loadErr)
		}
		if loadErr = newCfg.ResolveEnv(os.Getenv); loadErr != nil {
			return fail("resolve", loadErr)
		}
		if loadErr = newCfg.ResolveSecretFiles(nil); loadErr != nil {
			return fail("resolve", loadErr)
		}
		if loadErr = newCfg.Validate(); loadErr != nil {
			return fail("validate", loadErr)
		}
		newRt, loadErr := config.BuildRuntime(newCfg)
		if loadErr != nil {
			return fail("build", loadErr)
		}
		preparedObservability, loadErr := observabilityController.Prepare(context.Background(), newCfg.Observability)
		if loadErr != nil {
			return fail("observability", loadErr)
		}
		if loadErr = server.Reload(newCfg, newRt); loadErr != nil {
			abortCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if abortErr := preparedObservability.Abort(abortCtx); abortErr != nil {
				logger.Warn("prepared observability cleanup failed", "error", abortErr)
			}
			return fail("apply", loadErr)
		}
		if cleanupErr := observabilityController.Apply(context.Background(), preparedObservability); cleanupErr != nil {
			logger.Warn("retired observability cleanup failed", "error", cleanupErr)
		}
		configMu.Lock()
		cfg = newCfg
		configMu.Unlock()
		result.success = true
		result.debounce = newCfg.Reload.Debounce
		server.RecordConfigReload("success", "observability")
		logger.Info("config reloaded", "path", configPath, "stage", "observability")
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
