package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeSecret(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}

func TestResolveSecretFilesPopulatesTargets(t *testing.T) {
	t.Parallel()

	jwtSecret := writeSecret(t, "jwt", "  super-secret-value\n")
	clientSecret := writeSecret(t, "client", "client-secret\n")
	redisURL := writeSecret(t, "redis", "rediss://cache:6379\n")
	adminToken := writeSecret(t, "admin", "admin-token\n")
	healthToken := writeSecret(t, "health", "health-token\n")

	cfg := &Config{
		Listener: ListenerConfig{
			Admin: AdminConfig{TokenFile: adminToken},
			Health: HealthEndpointsConfig{
				Access: EndpointAccessConfig{TokenFile: healthToken},
			},
		},
		Middleware: []MiddlewareConfig{
			{Name: "jwt", Type: "jwt", Config: MiddlewareSettingsConfig{SecretFile: jwtSecret}},
			{Name: "oauth2", Type: "oauth2", Config: MiddlewareSettingsConfig{ClientSecretFile: clientSecret}},
			{Name: "rl", Type: "rate_limit", Config: MiddlewareSettingsConfig{RedisURLFile: redisURL}},
		},
	}

	if err := cfg.ResolveSecretFiles(nil); err != nil {
		t.Fatalf("ResolveSecretFiles() error = %v", err)
	}

	if got := cfg.Listener.Admin.ResolvedToken; got != "admin-token" {
		t.Errorf("admin token = %q, want admin-token", got)
	}
	if got := cfg.Listener.Health.Access.ResolvedToken; got != "health-token" {
		t.Errorf("health token = %q, want health-token", got)
	}
	if got := cfg.Middleware[0].Config.ResolvedSecret; got != "super-secret-value" {
		t.Errorf("jwt secret = %q, want super-secret-value (trimmed)", got)
	}
	if got := cfg.Middleware[1].Config.ResolvedClientSecret; got != "client-secret" {
		t.Errorf("client secret = %q, want client-secret", got)
	}
	if got := cfg.Middleware[2].Config.RedisURL; got != "rediss://cache:6379" {
		t.Errorf("redis url = %q, want rediss://cache:6379", got)
	}
}

func TestResolveSecretFilesEnvWinsWhenBothSet(t *testing.T) {
	t.Parallel()

	jwtSecret := writeSecret(t, "jwt", "from-file")
	cfg := &Config{
		Middleware: []MiddlewareConfig{
			{Name: "jwt", Type: "jwt", Config: MiddlewareSettingsConfig{
				SecretFile:     jwtSecret,
				ResolvedSecret: "from-env", // already resolved by ResolveEnv
			}},
		},
	}

	if err := cfg.ResolveSecretFiles(nil); err != nil {
		t.Fatalf("ResolveSecretFiles() error = %v", err)
	}
	if got := cfg.Middleware[0].Config.ResolvedSecret; got != "from-env" {
		t.Errorf("resolved secret = %q, want from-env (env must win)", got)
	}
}

func TestResolveSecretFilesMissingFileErrors(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		Middleware: []MiddlewareConfig{
			{Name: "jwt", Type: "jwt", Config: MiddlewareSettingsConfig{SecretFile: "/nonexistent/secret"}},
		},
	}
	if err := cfg.ResolveSecretFiles(nil); err == nil {
		t.Fatal("expected error for missing secret file")
	}
}

func TestResolveSecretFilesEmptyFileErrors(t *testing.T) {
	t.Parallel()

	empty := writeSecret(t, "empty", "   \n")
	cfg := &Config{
		Middleware: []MiddlewareConfig{
			{Name: "jwt", Type: "jwt", Config: MiddlewareSettingsConfig{SecretFile: empty}},
		},
	}
	if err := cfg.ResolveSecretFiles(nil); err == nil {
		t.Fatal("expected error for empty secret file")
	}
}

// A hs256 JWT middleware configured only with secret_file must pass validation.
func TestValidateJWTAcceptsSecretFile(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.Middleware = []MiddlewareConfig{
		{Name: "jwt-auth", Type: "jwt", Config: MiddlewareSettingsConfig{SecretFile: "/etc/relay/jwt.secret"}},
	}
	cfg.Routes[0].Middleware = []string{"jwt-auth"}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v (secret_file should satisfy hs256)", err)
	}
}
