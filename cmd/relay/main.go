package main

import (
	"context"
	"embed"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"algoryn.io/relay/internal/config"
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
