package main

import (
	"context"
	"log/slog"
	"embed"
	"flag"
	"log/slog"
	"net/http"
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
=======
	"algoryn.io/relay/internal/events"
	"algoryn.io/relay/internal/listener"
	"algoryn.io/relay/internal/middleware"
	"algoryn.io/relay/internal/observability"
	"algoryn.io/relay/internal/proxy"
	"algoryn.io/relay/internal/router"
	"algoryn.io/relay/internal/storage"
)

const (
	binaryVersion = "dev"
	defaultConfig = "config/example.yaml"
)

func main() {
	configPath := flag.String("config", defaultConfig, "path to relay YAML config")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}
	if cfg == nil {
		cfg = &config.Config{
			Listener: config.ListenerConfig{
				HTTP:  config.HTTPConfig{Port: 8088},
				HTTPS: config.HTTPSConfig{Port: 8443},
			},
			Storage: config.StorageConfig{Path: "./data/relay.db"},
		}
	}

	if err := config.Validate(cfg); err != nil {
		slog.Error("invalid config", "error", err)
		os.Exit(1)
	}

	logs := observability.New(cfg.Observability.Logs)
	eventBus := events.NewLogEventBus(logs.Slog())
	collector := observability.NewCollector(eventBus, 10*time.Second)

	store, err := storage.Open(cfg.Storage.Path)
	if err != nil {
		slog.Error("failed to open storage", "error", err)
		os.Exit(1)
	}
	defer func() {
		_ = store.Close()
	}()
	_ = store.Migrate()
	repo := storage.NewRepository(store)

	registry := proxy.NewConfigRegistry(cfg.Backends)
	balancer := proxy.NewRoundRobin()
	reverseProxy := proxy.New(registry, balancer)

	rt := router.New(cfg.Routes)
	finalHandler := middleware.Chain()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reverseProxy.ServeHTTP(w, r)
	}))

	var dashboardAssets embed.FS
	dashboard := observability.NewDashboard(repo, dashboardAssets)

	mux := http.NewServeMux()
	mux.Handle("/", finalHandler)
	mux.Handle("/dashboard/", http.StripPrefix("/dashboard", dashboard))
	mux.Handle("/routes/", rt)

	l := listener.New(listener.Options{
		HTTPPort:      cfg.Listener.HTTP.Port,
		HTTPSPort:     cfg.Listener.HTTPS.Port,
		TLSMode:       cfg.Listener.TLS.Mode,
		ReadTimeout:   cfg.Listener.Timeouts.ReadTimeout,
		WriteTimeout:  cfg.Listener.Timeouts.WriteTimeout,
		IdleTimeout:   cfg.Listener.Timeouts.IdleTimeout,
		HeaderTimeout: cfg.Listener.Timeouts.HeaderTimeout,
	}, mux)

	slog.Info("relay starting",
		"version", binaryVersion,
		"http_port", cfg.Listener.HTTP.Port,
		"https_port", cfg.Listener.HTTPS.Port,
	)

	go collector.Start(ctx)

	go func() {
		if err := l.Start(ctx); err != nil {
			slog.Error("listener stopped", "error", err)
			cancel()
		}
	}()

	<-ctx.Done()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := l.Shutdown(shutdownCtx); err != nil {
		slog.Error("graceful shutdown failed", "error", err)

		os.Exit(1)
	}
}
