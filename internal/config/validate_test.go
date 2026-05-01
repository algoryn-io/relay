package config

import (
	"strings"
	"testing"
	"time"
)

func TestValidateValidConfig(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateFabricEnabledRequiresServiceName(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.Observability.Fabric = FabricConfig{Enabled: true, ServiceName: ""}

	assertValidationErrorContains(t, cfg.Validate(), "observability.fabric.service_name")
}

func TestValidateJWTMappedClaimDuplicateDestination(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.Middleware[0].Config.ClaimsToHeaders = map[string]string{
		"role":  "X-Shared-Dest",
		"scope": "X-Shared-Dest",
	}

	assertValidationErrorContains(t, cfg.Validate(), `duplicate destination header "X-Shared-Dest"`)
}

func TestValidateDuplicateRouteNames(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.Routes = append(cfg.Routes, cfg.Routes[0])

	assertValidationErrorContains(t, cfg.Validate(), `duplicate value "orders-route"`)
}

func TestValidateMissingBackendReference(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.Routes[0].Backend = "missing"

	assertValidationErrorContains(t, cfg.Validate(), `unknown backend "missing"`)
}

func TestValidateMissingMiddlewareReference(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.Routes[0].Middleware = []string{"missing"}

	assertValidationErrorContains(t, cfg.Validate(), `unknown middleware "missing"`)
}

func TestValidateInvalidStrategy(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.Backends[0].Strategy = "random"

	assertValidationErrorContains(t, cfg.Validate(), "must be one of round_robin, least_connections")
}

func TestValidateInvalidURL(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.Backends[0].Instances[0].URL = "://bad"

	assertValidationErrorContains(t, cfg.Validate(), `invalid URL "://bad"`)
}

func TestValidateInvalidURLScheme(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.Backends[0].Instances[0].URL = "ftp://localhost:8080"

	assertValidationErrorContains(t, cfg.Validate(), "scheme must be http or https")
}

func TestValidateEmptyMethods(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.Routes[0].Match.Methods = nil

	assertValidationErrorContains(t, cfg.Validate(), "routes[0].match.methods: must not be empty")
}

func TestValidateInvalidPorts(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.Listener.HTTP.Port = 0
	cfg.Listener.HTTPS.Port = 0

	assertValidationErrorContains(t, cfg.Validate(), "listener: at least one of listener.http.port or listener.https.port must be greater than 0")
}

func TestValidateBodyLimitRequiresPositiveMaxBytes(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.Middleware = []MiddlewareConfig{
		{
			Name: "api-body-limit",
			Type: "body_limit",
			Config: MiddlewareSettingsConfig{
				MaxBytes: 0,
			},
		},
	}
	cfg.Routes[0].Middleware = []string{"api-body-limit"}

	assertValidationErrorContains(t, cfg.Validate(), "middleware[0].config.max_bytes: must be greater than 0")
}

func TestValidateBodyLimitValidConfig(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.Middleware = []MiddlewareConfig{
		{
			Name: "api-body-limit",
			Type: "body_limit",
			Config: MiddlewareSettingsConfig{
				MaxBytes: 1024,
			},
		},
	}
	cfg.Routes[0].Middleware = []string{"api-body-limit"}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateCORSMiddleware(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.Middleware = append(cfg.Middleware, MiddlewareConfig{
		Name: "api-cors",
		Type: "cors",
		Config: MiddlewareSettingsConfig{
			AllowedOrigins: []string{"http://localhost:3000"},
			AllowedMethods: []string{"GET", "POST", "OPTIONS"},
			AllowedHeaders: []string{"Authorization", "Content-Type"},
		},
	})

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateIPFilterRequiresAllowOrDeny(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.Middleware = []MiddlewareConfig{
		{
			Name:   "admin-ip-filter",
			Type:   "ip_filter",
			Config: MiddlewareSettingsConfig{},
		},
	}
	cfg.Routes[0].Middleware = []string{"admin-ip-filter"}

	assertValidationErrorContains(t, cfg.Validate(), "at least one of allow or deny must be provided")
}

func TestValidateIPFilterInvalidEntry(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.Middleware = []MiddlewareConfig{
		{
			Name: "admin-ip-filter",
			Type: "ip_filter",
			Config: MiddlewareSettingsConfig{
				Allow: []string{"bad-ip"},
			},
		},
	}
	cfg.Routes[0].Middleware = []string{"admin-ip-filter"}

	assertValidationErrorContains(t, cfg.Validate(), "must be a valid IP or CIDR")
}

func TestValidateIPFilterValidConfig(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.Middleware = []MiddlewareConfig{
		{
			Name: "admin-ip-filter",
			Type: "ip_filter",
			Config: MiddlewareSettingsConfig{
				Allow: []string{"192.168.1.0/24", "10.0.0.1"},
				Deny:  []string{"192.168.1.10"},
			},
		},
	}
	cfg.Routes[0].Middleware = []string{"admin-ip-filter"}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateLogsFileBlankAfterTrim(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.Observability.Logs.File = "   "

	assertValidationErrorContains(t, cfg.Validate(), "observability.logs.file: must not be blank")
}

func TestValidateLogsMaxSizeNegative(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.Observability.Logs.MaxSizeMB = -1

	assertValidationErrorContains(t, cfg.Validate(), "observability.logs.max_size_mb: must be >= 0")
}

func assertValidationErrorContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected validation error containing %q, got nil", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("validation error = %q, want substring %q", err.Error(), want)
	}
}

func validConfig() *Config {
	return &Config{
		Listener: ListenerConfig{
			HTTP: HTTPConfig{Port: 8080},
			Timeouts: TimeoutsConfig{
				Read:  30 * time.Second,
				Write: 30 * time.Second,
				Idle:  60 * time.Second,
			},
		},
		Routes: []RouteConfig{
			{
				Name:       "orders-route",
				Backend:    "orders-backend",
				Middleware: []string{"jwt-auth"},
				Match: MatchConfig{
					Path:    "/api/orders",
					Methods: []string{"GET", "POST"},
				},
			},
		},
		Backends: []BackendConfig{
			{
				Name:     "orders-backend",
				Strategy: "round_robin",
				HealthCheck: HealthCheckConfig{
					Interval: 10 * time.Second,
					Timeout:  2 * time.Second,
					Path:     "/health",
				},
				Instances: []InstanceConfig{
					{URL: "http://localhost:8080"},
				},
			},
		},
		Middleware: []MiddlewareConfig{
			{
				Name: "jwt-auth",
				Type: "jwt",
				Config: MiddlewareSettingsConfig{
					SecretEnv: "JWT_SECRET",
					Header:    "Authorization",
				},
			},
		},
		Observability: ObservabilityConfig{
			Metrics: MetricsConfig{FlushInterval: 30 * time.Second},
		},
		Storage: StorageConfig{Path: "./data"},
		Reload:  ReloadConfig{Watch: true, Debounce: 500 * time.Millisecond},
	}
}
