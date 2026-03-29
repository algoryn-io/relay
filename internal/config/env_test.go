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

	if got := cfg.Middleware[0].Config.Secret; got != "top-secret" {
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
