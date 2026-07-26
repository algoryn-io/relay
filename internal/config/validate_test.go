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

func TestValidateAdminOutsideLoopbackRequiresToken(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.Listener.Admin.AllowedCIDRs = []string{"10.0.0.0/8"}

	assertValidationErrorContains(t, cfg.Validate(), "listener.admin: token_env or token_file is required")
}

func TestValidateAdminLoopbackCanUseIPOnlyAccess(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.Listener.Admin.AllowedCIDRs = []string{"127.0.0.0/8", "::1/128"}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateRejectsPublicTrustedNetworks(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.Listener.TrustedProxies = []string{"0.0.0.0/0"}
	assertValidationErrorContains(t, cfg.Validate(), "listener.trusted_proxies[0]: public CIDRs")

	cfg = validConfig()
	cfg.Observability.Prometheus.AllowedCIDRs = []string{"::/0"}
	assertValidationErrorContains(t, cfg.Validate(), "observability.prometheus.allowed_cidrs[0]: public CIDRs")
}

func TestValidateInsecureBackendTLSRequiresAcknowledgement(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.Backends[0].TLS.InsecureSkipVerify = true

	assertValidationErrorContains(t, cfg.Validate(), "acknowledge_insecure_skip_verify")
	cfg.Backends[0].TLS.AcknowledgeInsecureSkipVerify = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() explicit acknowledgement error = %v", err)
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

func TestValidateRejectsNegativePerIPConnectionLimit(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.Listener.MaxConnectionsPerIP = -1

	assertValidationErrorContains(t, cfg.Validate(), "listener.max_connections_per_ip: must be >= 0")
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

func TestValidateBackendProtocolInvalid(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.Backends[0].Protocol = "http3"

	assertValidationErrorContains(t, cfg.Validate(), "protocol: must be one of http1, h2c")
}

func TestValidateBackendH2CWithTLSConflict(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.Backends[0].Protocol = "h2c"
	cfg.Backends[0].TLS = BackendTLSConfig{CAFile: "/etc/relay/ca.pem"}

	assertValidationErrorContains(t, cfg.Validate(), "h2c (cleartext) cannot be combined with tls")
}

func TestValidateBackendH2CValid(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.Backends[0].Protocol = "h2c"

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateOAuth2RequiresHTTPSAndClient(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.Middleware = []MiddlewareConfig{
		{
			Name: "introspect",
			Type: "oauth2",
			Config: MiddlewareSettingsConfig{
				IntrospectionURL: "http://idp.example.com/introspect", // plaintext
				ClientID:         "relay",
				ClientSecretEnv:  "SECRET",
			},
		},
	}
	cfg.Routes[0].Middleware = []string{"introspect"}

	assertValidationErrorContains(t, cfg.Validate(), "introspection_url: must be an https URL")
}

func TestValidateOAuth2ValidConfig(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.Middleware = []MiddlewareConfig{
		{
			Name: "introspect",
			Type: "oauth2",
			Config: MiddlewareSettingsConfig{
				IntrospectionURL: "https://idp.example.com/introspect",
				ClientID:         "relay",
				ClientSecretEnv:  "SECRET",
				RequiredScopes:   []string{"read"},
			},
		},
	}
	cfg.Routes[0].Middleware = []string{"introspect"}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateExtAuthzRequiresURL(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.Middleware = []MiddlewareConfig{
		{
			Name:   "authz",
			Type:   "ext_authz",
			Config: MiddlewareSettingsConfig{},
		},
	}
	cfg.Routes[0].Middleware = []string{"authz"}

	assertValidationErrorContains(t, cfg.Validate(), "authz_url: required")
}

func TestValidateExtAuthzFailOpenRequiresSeparateAcknowledgement(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.Middleware = []MiddlewareConfig{{
		Name: "authz",
		Type: "ext_authz",
		Config: MiddlewareSettingsConfig{
			AuthzURL:                    "https://authz.example.com/check",
			FailOpen:                    true,
			AcknowledgeAPIKeyInQuery:    true,
			AcknowledgeExtAuthzFailOpen: false,
		},
	}}
	cfg.Routes[0].Middleware = []string{"authz"}

	assertValidationErrorContains(t, cfg.Validate(), "acknowledge_ext_authz_fail_open: must be true")

	cfg.Middleware[0].Config.AcknowledgeExtAuthzFailOpen = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() explicit acknowledgement error = %v", err)
	}
}

func TestValidateAPIKeyQueryRequiresSeparateAcknowledgement(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.Middleware = []MiddlewareConfig{{
		Name: "api-key",
		Type: "api_key",
		Config: MiddlewareSettingsConfig{
			KeyQuery:                    "api_key",
			KeysEnv:                     "RELAY_API_KEYS",
			AcknowledgeAPIKeyInQuery:    false,
			AcknowledgeExtAuthzFailOpen: true,
		},
	}}
	cfg.Routes[0].Middleware = []string{"api-key"}

	assertValidationErrorContains(t, cfg.Validate(), "acknowledge_api_key_in_query: must be true")

	cfg.Middleware[0].Config.AcknowledgeAPIKeyInQuery = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() explicit acknowledgement error = %v", err)
	}
}

func TestValidateAPIKeyHeaderDoesNotRequireDangerousOptionAcknowledgement(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.Middleware = []MiddlewareConfig{{
		Name: "api-key",
		Type: "api_key",
		Config: MiddlewareSettingsConfig{
			KeyHeader: "X-API-Key",
			KeysEnv:   "RELAY_API_KEYS",
		},
	}}
	cfg.Routes[0].Middleware = []string{"api-key"}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() header-only API key error = %v", err)
	}
}

func TestValidateRateLimitFailOpenDoesNotRequireExtAuthzAcknowledgement(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.Middleware = []MiddlewareConfig{{
		Name: "redis-rate-limit",
		Type: "rate_limit",
		Config: MiddlewareSettingsConfig{
			Strategy:       "sliding_window",
			Limit:          100,
			Window:         time.Minute,
			By:             "ip",
			RateLimitStore: "redis",
			RedisURL:       "redis://localhost:6379",
			FailOpen:       true,
		},
	}}
	cfg.Routes[0].Middleware = []string{"redis-rate-limit"}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() rate-limit fail_open error = %v", err)
	}
}

func TestValidateCacheInvalidStatus(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.Middleware = []MiddlewareConfig{
		{
			Name: "page-cache",
			Type: "cache",
			Config: MiddlewareSettingsConfig{
				CacheableStatus: []int{99},
			},
		},
	}
	cfg.Routes[0].Middleware = []string{"page-cache"}

	assertValidationErrorContains(t, cfg.Validate(), "cacheable_status[0]: must be a valid HTTP status code")
}

func TestValidateJWTOIDCRequiresHTTPS(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.Middleware = []MiddlewareConfig{
		{
			Name: "jwt-oidc",
			Type: "jwt",
			Config: MiddlewareSettingsConfig{
				Algorithm:  "rs256",
				OIDCIssuer: "http://issuer.example.com", // plaintext
			},
		},
	}
	cfg.Routes[0].Middleware = []string{"jwt-oidc"}

	assertValidationErrorContains(t, cfg.Validate(), "oidc_issuer: must be an https URL")
}

func TestValidateJWTRemoteKeysRequireIssuerAndAudience(t *testing.T) {
	t.Parallel()

	tests := map[string]MiddlewareSettingsConfig{
		"jwks": {
			Algorithm: "rs256",
			JWKSUrl:   "https://issuer.example.com/.well-known/jwks.json",
		},
		"oidc": {
			Algorithm:  "rs256",
			OIDCIssuer: "https://issuer.example.com",
		},
	}

	for name, settings := range tests {
		name, settings := name, settings
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg := validConfig()
			cfg.Middleware[0].Config = settings

			err := cfg.Validate()
			assertValidationErrorContains(t, err, "issuer: required for rs256 with remote JWKS or OIDC discovery")
			assertValidationErrorContains(t, err, "audience: required for rs256 with remote JWKS or OIDC discovery")

			cfg.Middleware[0].Config.ExpectedIssuer = "https://issuer.example.com"
			cfg.Middleware[0].Config.ExpectedAudience = "relay-api"
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate() remote JWT with bound claims error = %v", err)
			}
		})
	}
}

func TestValidateJWKSStaleGraceBounds(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		grace time.Duration
		want  string
	}{
		"negative": {
			grace: -time.Second,
			want:  "jwks_stale_grace: must be >= 0",
		},
		"over maximum": {
			grace: maxJWKSStaleGrace + time.Second,
			want:  "jwks_stale_grace: must be <= 24h0m0s",
		},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := validConfig()
			cfg.Middleware[0].Config = MiddlewareSettingsConfig{
				Algorithm:        "rs256",
				JWKSUrl:          "https://issuer.example.com/jwks",
				JWKSStaleGrace:   tc.grace,
				ExpectedIssuer:   "https://issuer.example.com",
				ExpectedAudience: "relay-api",
			}
			assertValidationErrorContains(t, cfg.Validate(), tc.want)
		})
	}
}

func TestValidateJWTLocalKeysDoNotRequireIssuerOrAudience(t *testing.T) {
	t.Parallel()

	tests := map[string]MiddlewareSettingsConfig{
		"hs256": {
			Algorithm: "hs256",
			SecretEnv: "JWT_SECRET",
		},
		"static-pem": {
			Algorithm:     "rs256",
			PublicKeyFile: "/etc/relay/public.pem",
		},
	}

	for name, settings := range tests {
		name, settings := name, settings
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg := validConfig()
			cfg.Middleware[0].Config = settings
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate() local JWT without issuer/audience error = %v", err)
			}
		})
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
		Reload: ReloadConfig{Watch: true, Debounce: 500 * time.Millisecond},
	}
}
