package config

import (
	"strings"
	"testing"
)

func TestResolveEnvJWTSecret(t *testing.T) {
	t.Parallel()

	cfg := validConfig()

	err := cfg.ResolveEnv(func(key string) string {
		if key == "JWT_SECRET" {
			return "top-secret"
		}
		return ""
	})
	if err != nil {
		t.Fatalf("ResolveEnv() error = %v", err)
	}

	if got := cfg.Middleware[0].Config.ResolvedSecret; got != "top-secret" {
		t.Fatalf("resolved secret = %q, want top-secret", got)
	}
}

func TestResolveEnvMissingVariable(t *testing.T) {
	t.Parallel()

	cfg := validConfig()

	err := cfg.ResolveEnv(func(string) string { return "" })
	if err == nil {
		t.Fatal("ResolveEnv() error = nil, want missing env error")
	}
	if !strings.Contains(err.Error(), `environment variable "JWT_SECRET" is not set`) {
		t.Fatalf("ResolveEnv() error = %q", err.Error())
	}
}

func TestResolveEnvAccessHashAndOTLPHeaders(t *testing.T) {
	t.Parallel()
	cfg := &Config{Observability: ObservabilityConfig{Logs: LogsConfig{
		Access: AccessLogConfig{Hash: AccessLogHashConfig{SecretEnv: "HASH_SECRET"}},
		OTLP:   OTLPLogsConfig{HeadersEnv: "OTLP_HEADERS"},
	}}}
	err := cfg.ResolveEnv(func(key string) string {
		switch key {
		case "HASH_SECRET":
			return "correlation-secret"
		case "OTLP_HEADERS":
			return "Authorization=Bearer%20collector"
		default:
			return ""
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Observability.Logs.Access.Hash.ResolvedSecret != "correlation-secret" {
		t.Fatal("hash secret was not resolved")
	}
	if cfg.Observability.Logs.OTLP.ResolvedHeaders != "Authorization=Bearer%20collector" {
		t.Fatal("OTLP headers were not resolved")
	}
}
