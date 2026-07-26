package config

import "time"

type Config struct {
	// Include lists additional config files (relative to this file's directory,
	// or absolute) whose routes, backends and middleware are merged into this
	// config. Includes are loaded once (idempotent), so shared bases and cycles
	// are handled safely. Other sections (listener, observability, ...) come from
	// the top-level file.
	Include       []string            `yaml:"include"`
	Listener      ListenerConfig      `yaml:"listener"`
	Routes        []RouteConfig       `yaml:"routes"`
	Backends      []BackendConfig     `yaml:"backends"`
	Middleware    []MiddlewareConfig  `yaml:"middleware"`
	Observability ObservabilityConfig `yaml:"observability"`
	// Storage is retained only for backwards-compatible parsing. Relay does not
	// persist request, metrics, or log data; use external storage instead.
	Storage StorageConfig `yaml:"storage"`
	Reload  ReloadConfig  `yaml:"reload"`
}

type ListenerConfig struct {
	HTTP           HTTPConfig     `yaml:"http"`
	HTTPS          HTTPSConfig    `yaml:"https"`
	TLS            TLSConfig      `yaml:"tls"`
	Timeouts       TimeoutsConfig `yaml:"timeouts"`
	TrustedProxies []string       `yaml:"trusted_proxies"`
	Admin          AdminConfig    `yaml:"admin"`
	// StripRequestHeaders lists additional inbound headers to remove at the edge
	// before any routing or proxying, on top of the always-stripped Relay-managed
	// identity headers. Use it for app-specific identity headers a backend trusts
	// (e.g. X-User-Id, X-Roles) so clients cannot spoof them.
	StripRequestHeaders []string `yaml:"strip_request_headers"`
	// MaxConcurrentRequests caps in-flight proxied requests across all routes
	// (global overload backpressure on top of per-backend bulkheads). Excess
	// requests get a fast 503. 0 means unlimited.
	MaxConcurrentRequests int `yaml:"max_concurrent_requests"`
}

// AdminConfig controls access to the /_relay/admin/* management endpoints.
type AdminConfig struct {
	// AllowedCIDRs is the list of IP ranges that may call admin endpoints.
	// Defaults to loopback only (127.0.0.0/8 and ::1/128) when empty.
	AllowedCIDRs []string `yaml:"allowed_cidrs"`
	// TokenEnv names an environment variable holding a bearer token. When set,
	// admin requests must present "Authorization: Bearer <token>" in addition to
	// passing the IP allowlist. Leave empty for IP-only access.
	TokenEnv string `yaml:"token_env"`
	// TokenFile reads the admin bearer token from a mounted file. Alternative to
	// token_env; token_env wins if both are set.
	TokenFile     string `yaml:"token_file"`
	ResolvedToken string `yaml:"-"`
}

type HTTPConfig struct {
	Port int `yaml:"port"`
}

type HTTPSConfig struct {
	Port int       `yaml:"port"`
	TLS  TLSConfig `yaml:"tls"`
}

type TLSConfig struct {
	Mode     string   `yaml:"mode"`
	Domains  []string `yaml:"domains"`
	CertFile string   `yaml:"cert_file"`
	KeyFile  string   `yaml:"key_file"`
	// ACMECacheDir is the writable, persistent cache directory used by TLS
	// mode "auto". It must be mounted in container deployments.
	ACMECacheDir string `yaml:"acme_cache_dir"`
	// MinVersion is the minimum accepted TLS version: "1.2" (default) or "1.3".
	MinVersion string `yaml:"min_version"`
	// ClientCAFile, when set, enables inbound mTLS: clients must present a
	// certificate signed by a CA in this PEM bundle.
	ClientCAFile string `yaml:"client_ca_file"`
	// ClientAuth selects the client-certificate policy when ClientCAFile is set:
	// "require" (default) verifies a cert is presented and valid; "verify_if_given"
	// verifies only when one is presented; "request" asks but does not enforce.
	ClientAuth string `yaml:"client_auth"`
}

type TimeoutsConfig struct {
	Read  time.Duration `yaml:"read"`
	Write time.Duration `yaml:"write"`
	Idle  time.Duration `yaml:"idle"`
	// ReadHeader bounds how long reading request headers may take (Slowloris
	// mitigation). Defaults to 10s when zero.
	ReadHeader time.Duration `yaml:"read_header"`
	// WebSocketIdle closes a proxied WebSocket/upgrade tunnel after this much
	// idle time on the client connection. 0 disables it (no idle timeout).
	WebSocketIdle time.Duration `yaml:"websocket_idle"`
	ReadTimeout   time.Duration `yaml:"-"`
	WriteTimeout  time.Duration `yaml:"-"`
	IdleTimeout   time.Duration `yaml:"-"`
}

// RewriteRule rewrites the outbound request path using a regular expression
// before the request is forwarded to the backend. Pattern uses RE2 syntax;
// capture groups can be referenced as $1, $2 or ${name} in Replacement.
// Applied after strip_prefix and before the request reaches the backend.
type RewriteRule struct {
	// Pattern is a RE2 regular expression matched against the request path.
	Pattern string `yaml:"pattern"`
	// Replacement is the substitution string. Use $1/$2 or ${name} to
	// reference numbered or named capture groups from Pattern.
	Replacement string `yaml:"replacement"`
}

type RouteConfig struct {
	Name        string        `yaml:"name"`
	ID          string        `yaml:"id"`
	Match       MatchConfig   `yaml:"match"`
	Middleware  []string      `yaml:"middleware"`
	Middlewares []string      `yaml:"-"`
	Backend     string        `yaml:"backend"`
	StripPrefix string        `yaml:"-"` // set via UnmarshalYAML
	Timeout     time.Duration `yaml:"-"` // set via UnmarshalYAML
	// MaxBodyBytes caps the request body size for this route. Requests with a
	// larger body are rejected with 413. 0 means no limit.
	MaxBodyBytes int64 `yaml:"-"` // set via UnmarshalYAML
	// Rewrite applies a regex rewrite to the request path before proxying.
	// Leave Pattern empty to disable.
	Rewrite RewriteRule `yaml:"-"` // set via UnmarshalYAML
	// AddRequestHeaders injects headers into the outbound request.
	// Values of the form "${req.HEADER-NAME}" copy the named incoming header.
	// All other values are used verbatim.
	AddRequestHeaders map[string]string `yaml:"-"` // set via UnmarshalYAML
}

type MatchConfig struct {
	Path       string   `yaml:"path"`
	PathPrefix string   `yaml:"path_prefix"`
	Methods    []string `yaml:"methods"`
	// Hosts restricts the route to requests whose Host header (port stripped,
	// case-insensitive) matches one of these values. Empty means any host.
	Hosts []string `yaml:"hosts"`
	// Headers requires each listed request header to equal the given value
	// (case-insensitive header name, case-sensitive value). Empty means no
	// header constraint. Useful for canary routing and API versioning.
	Headers map[string]string `yaml:"headers"`
	// Query requires each listed query parameter to equal the given value.
	// Empty means no query constraint.
	Query map[string]string `yaml:"query"`
}

type BackendConfig struct {
	Name string `yaml:"name"`
	// Protocol selects the wire protocol used to reach this backend:
	//   "http1" (default) — HTTP/1.1, with HTTP/2 negotiated via ALPN for https.
	//   "h2c"             — HTTP/2 over cleartext (prior knowledge), for gRPC and
	//                       streaming backends that do not terminate TLS.
	Protocol       string               `yaml:"protocol"`
	Strategy       string               `yaml:"strategy"`
	HealthCheck    HealthCheckConfig    `yaml:"health_check"`
	CircuitBreaker CircuitBreakerConfig `yaml:"circuit_breaker"`
	Retry          RetryConfig          `yaml:"retry"`
	TLS            BackendTLSConfig     `yaml:"tls"`
	Bulkhead       BulkheadConfig       `yaml:"bulkhead"`
	Instances      []InstanceConfig     `yaml:"instances"`
}

// BulkheadConfig caps the number of simultaneous in-flight requests to a
// backend. Set MaxConcurrent > 0 to enable; 0 disables the bulkhead.
type BulkheadConfig struct {
	// MaxConcurrent is the maximum number of requests that may be in flight to
	// this backend at the same time. Requests that arrive when the limit is
	// reached are immediately rejected with 503 (fail fast, no queuing).
	MaxConcurrent int `yaml:"max_concurrent"`
}

// BackendTLSConfig controls outbound TLS toward a backend.
// All fields are optional. Set CertFile+KeyFile for mutual TLS (mTLS).
// Set CAFile to trust a private CA instead of the system root store.
type BackendTLSConfig struct {
	// CertFile is the path to the PEM-encoded client certificate for mTLS.
	CertFile string `yaml:"cert_file"`
	// KeyFile is the path to the PEM-encoded private key for mTLS.
	KeyFile string `yaml:"key_file"`
	// CAFile is the path to a PEM-encoded CA certificate bundle used to
	// verify the backend server certificate. Uses the system pool when empty.
	CAFile string `yaml:"ca_file"`
	// InsecureSkipVerify disables server certificate verification.
	// For development and testing only — never use in production.
	InsecureSkipVerify bool `yaml:"insecure_skip_verify"`
}

// RetryConfig enables request retries with exponential backoff for a backend.
// Set Attempts > 1 and at least one entry in On to enable retries.
type RetryConfig struct {
	// Attempts is the maximum total number of attempts (including the first).
	// 0 or 1 disables retry.
	Attempts int `yaml:"attempts"`
	// BackoffInit is the initial backoff duration. Defaults to 100ms.
	BackoffInit time.Duration `yaml:"backoff_init"`
	// BackoffMax caps the backoff duration. Defaults to 1s.
	BackoffMax time.Duration `yaml:"backoff_max"`
	// On lists the conditions that trigger a retry: "5xx" and/or "network_error".
	On []string `yaml:"on"`
	// AllowUnsafe, when true, permits retrying non-safe HTTP methods
	// (POST, PUT, PATCH, DELETE). Use only when the upstream is idempotent.
	AllowUnsafe bool `yaml:"allow_unsafe"`
	// BudgetRatio caps retries as a fraction of request volume to prevent retry
	// storms during an outage. Each completed request replenishes this many
	// tokens; each retry costs one. 0 (default) disables the budget (retries are
	// governed only by Attempts). Example: 0.2 caps sustained retries at ~20% of
	// traffic.
	BudgetRatio float64 `yaml:"budget_ratio"`
	// BudgetTokens is the token bucket capacity (initial burst allowance) when
	// BudgetRatio > 0. Defaults to 100 when zero.
	BudgetTokens int `yaml:"budget_tokens"`
}

// CircuitBreakerConfig enables a per-instance circuit breaker for a backend.
// Set Threshold > 0 to enable; zero disables it.
type CircuitBreakerConfig struct {
	// Threshold is the number of consecutive failures that trip the circuit.
	Threshold int `yaml:"threshold"`
	// Timeout is how long the circuit stays open before allowing a probe.
	// Defaults to 30s when zero.
	Timeout time.Duration `yaml:"timeout"`
}

type HealthCheckConfig struct {
	Interval time.Duration `yaml:"interval"`
	Timeout  time.Duration `yaml:"timeout"`
	Path     string        `yaml:"path"`
}

type InstanceConfig struct {
	ID  string `yaml:"id"`
	URL string `yaml:"url"`
	// Weight controls traffic share when strategy is "weighted_random".
	// Must be >= 0; 0 is treated as 1. Ignored by other strategies.
	Weight int `yaml:"weight"`
}

type MiddlewareConfig struct {
	Name    string                   `yaml:"name"`
	Type    string                   `yaml:"type"`
	Enabled bool                     `yaml:"enabled"`
	Config  MiddlewareSettingsConfig `yaml:"config"`
}

type MiddlewareSettingsConfig struct {
	SecretEnv string `yaml:"secret_env"`
	// SecretFile reads the JWT HS256 secret from a mounted file (e.g. a Kubernetes
	// Secret volume). Trimmed of trailing whitespace. Alternative to secret_env;
	// secret_env wins if both are set.
	SecretFile      string            `yaml:"secret_file"`
	ResolvedSecret  string            `yaml:"-"`
	Header          string            `yaml:"header"`
	ClaimsToHeaders map[string]string `yaml:"claims_to_headers"`
	// JWT algorithm selection: hs256 (default), rs256.
	Algorithm string `yaml:"algorithm"`
	// PublicKeyFile is the path to a PEM-encoded RSA public key for rs256.
	PublicKeyFile string `yaml:"public_key_file"`
	// JWKSUrl is a JWKS endpoint URL for rs256 key discovery.
	JWKSUrl string `yaml:"jwks_url"`
	// JWKSCacheTTL is how long JWKS keys are cached. Defaults to 5m when zero.
	JWKSCacheTTL time.Duration `yaml:"jwks_cache_ttl"`
	// ExpectedIssuer, when set, requires the JWT "iss" claim to match exactly.
	ExpectedIssuer string `yaml:"issuer"`
	// ExpectedAudience, when set, requires the JWT "aud" claim to contain it.
	ExpectedAudience string        `yaml:"audience"`
	MaxBytes         int64         `yaml:"max_bytes"`
	Allow            []string      `yaml:"allow"`
	Deny             []string      `yaml:"deny"`
	Strategy         string        `yaml:"strategy"`
	Limit            int           `yaml:"limit"`
	Window           time.Duration `yaml:"window"`
	By               string        `yaml:"by"`
	// Rate limit store: "memory" (default, in-process) or "redis" (distributed).
	RateLimitStore string `yaml:"store"`
	// RedisURL is the connection URL for the Redis rate limit store.
	// Accepts redis:// and rediss:// (TLS) schemes. Use redis_url_env for
	// production to avoid credentials in config files.
	RedisURL string `yaml:"redis_url"`
	// RedisURLEnv is the name of an environment variable containing the
	// Redis URL; overrides redis_url when set.
	RedisURLEnv string `yaml:"redis_url_env"`
	// RedisURLFile reads the Redis URL from a mounted file. Alternative to
	// redis_url/redis_url_env.
	RedisURLFile     string   `yaml:"redis_url_file"`
	AllowedOrigins   []string `yaml:"allowed_origins"`
	AllowedMethods   []string `yaml:"allowed_methods"`
	AllowedHeaders   []string `yaml:"allowed_headers"`
	AllowCredentials bool     `yaml:"allow_credentials"`
	// JWTLogFailures emits structured Warn logs on JWT rejection (missing header, parse/signature/claims).
	// Does not log the raw token or secret; payload inspection lists claim keys and exp only.
	JWTLogFailures bool `yaml:"jwt_log_failures"`
	// Header middleware fields
	RequestSet  map[string]string `yaml:"request_set"`
	RequestDel  []string          `yaml:"request_del"`
	ResponseSet map[string]string `yaml:"response_set"`
	ResponseDel []string          `yaml:"response_del"`
	// API key middleware fields
	KeyHeader    string `yaml:"key_header"`
	KeyQuery     string `yaml:"key_query"`
	KeysEnv      string `yaml:"keys_env"`
	ResolvedKeys string `yaml:"-"` // populated from KeysEnv by ResolveEnv
	KeysFile     string `yaml:"keys_file"`
	KeyToHeader  string `yaml:"key_to_header"`
	// Cache middleware fields
	TTL             time.Duration `yaml:"ttl"`
	CacheMethods    []string      `yaml:"methods"`
	CacheableStatus []int         `yaml:"cacheable_status"`
	MaxObjectBytes  int64         `yaml:"max_object_bytes"`
	MaxEntries      int           `yaml:"max_entries"`
	Vary            []string      `yaml:"vary"`
	// OIDC discovery for jwt middleware: derive jwks_uri from the issuer's
	// well-known document instead of configuring jwks_url directly.
	OIDCIssuer string `yaml:"oidc_issuer"`
	// OAuth2 token introspection middleware (RFC 7662) fields.
	IntrospectionURL string `yaml:"introspection_url"`
	ClientID         string `yaml:"client_id"`
	ClientSecretEnv  string `yaml:"client_secret_env"`
	// ClientSecretFile reads the introspection client secret from a mounted file.
	// Alternative to client_secret_env.
	ClientSecretFile      string        `yaml:"client_secret_file"`
	ResolvedClientSecret  string        `yaml:"-"` // populated from ClientSecretEnv/ClientSecretFile
	RequiredScopes        []string      `yaml:"required_scopes"`
	IntrospectionCacheTTL time.Duration `yaml:"cache_ttl"`
	// External authorization middleware (ext_authz) fields.
	AuthzURL            string        `yaml:"authz_url"`
	AuthzForwardHeaders []string      `yaml:"forward_headers"`
	AuthzCopyHeaders    []string      `yaml:"copy_headers"`
	AuthzTimeout        time.Duration `yaml:"authz_timeout"`
	FailOpen            bool          `yaml:"fail_open"`
}

type ObservabilityConfig struct {
	// Dashboard is retained only for backwards-compatible parsing. Use the
	// shipped Grafana dashboard; Relay does not host a dashboard server.
	Dashboard DashboardConfig `yaml:"dashboard"`
	Logs      LogsConfig      `yaml:"logs"`
	// Metrics is retained for backwards-compatible parsing. Metrics are exposed
	// immediately; no in-process flush interval exists.
	Metrics    MetricsConfig    `yaml:"metrics"`
	Fabric     FabricConfig     `yaml:"fabric"`
	Prometheus PrometheusConfig `yaml:"prometheus"`
	Tracing    TracingConfig    `yaml:"tracing"`
}

// TracingConfig controls OpenTelemetry distributed tracing.
type TracingConfig struct {
	// Enabled activates tracing. When false, a no-op tracer is used.
	Enabled bool `yaml:"enabled"`
	// Exporter selects the trace exporter: "otlp_grpc", "otlp_http", or "stdout".
	Exporter string `yaml:"exporter"`
	// Endpoint is the collector address (e.g. "localhost:4317" for OTLP gRPC).
	// Defaults to the OpenTelemetry SDK default when empty.
	Endpoint string `yaml:"endpoint"`
	// SampleRate is the fraction of traces to sample (0.0–1.0). Default 1.0.
	SampleRate float64 `yaml:"sample_rate"`
	// ServiceName overrides the service name reported to the collector.
	// Falls back to observability.fabric.service_name, then "relay".
	ServiceName string `yaml:"service_name"`
}

type PrometheusConfig struct {
	// Path is the scrape endpoint. Defaults to /_relay/metrics/prometheus when empty.
	Path string `yaml:"path"`
	// AllowedCIDRs lists IP ranges (in addition to loopback) allowed to reach the
	// metrics and Prometheus endpoints, matched against the real TCP peer. Empty
	// (default) keeps the endpoints loopback-only. Set the pod/cluster CIDR to let
	// a Prometheus scraper (e.g. a ServiceMonitor) reach them.
	AllowedCIDRs []string `yaml:"allowed_cidrs"`
}

// FabricConfig controls Algoryn Fabric protobuf telemetry (MetricSnapshot + Event) toward Beacon and peers.
type FabricConfig struct {
	Enabled     bool   `yaml:"enabled"`
	ServiceName string `yaml:"service_name"`
	QueueSize   int    `yaml:"queue_size"`
}

type DashboardConfig struct {
	Enabled bool   `yaml:"enabled"`
	Port    int    `yaml:"port"`
	Path    string `yaml:"path"`
}

type LogsConfig struct {
	Level      string `yaml:"level"`
	Format     string `yaml:"format"`
	File       string `yaml:"file"`
	MaxSizeMB  int    `yaml:"max_size_mb"`
	MaxAgeDays int    `yaml:"max_age_days"`
	Compress   bool   `yaml:"compress"`
}

type MetricsConfig struct {
	FlushInterval time.Duration `yaml:"flush_interval"`
}

type StorageConfig struct {
	Path      string          `yaml:"path"`
	Retention RetentionConfig `yaml:"retention"`
}

type RetentionConfig struct {
	RequestsDays int `yaml:"requests_days"`
	MetricsDays  int `yaml:"metrics_days"`
	LogsDays     int `yaml:"logs_days"`
}

type ReloadConfig struct {
	Watch    bool          `yaml:"watch"`
	Enabled  bool          `yaml:"enabled"`
	Debounce time.Duration `yaml:"debounce"`
}

func (c *Config) Validate() error {
	if c == nil {
		return errNilConfig
	}
	return validateConfig(c)
}

func Validate(c *Config) error {
	if c == nil {
		return errNilConfig
	}
	return c.Validate()
}
