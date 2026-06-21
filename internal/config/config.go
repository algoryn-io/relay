package config

import "time"

type Config struct {
	Listener      ListenerConfig      `yaml:"listener"`
	Routes        []RouteConfig       `yaml:"routes"`
	Backends      []BackendConfig     `yaml:"backends"`
	Middleware    []MiddlewareConfig  `yaml:"middleware"`
	Observability ObservabilityConfig `yaml:"observability"`
	Storage       StorageConfig       `yaml:"storage"`
	Reload        ReloadConfig        `yaml:"reload"`
}

type ListenerConfig struct {
	HTTP           HTTPConfig     `yaml:"http"`
	HTTPS          HTTPSConfig    `yaml:"https"`
	TLS            TLSConfig      `yaml:"tls"`
	Timeouts       TimeoutsConfig `yaml:"timeouts"`
	TrustedProxies []string       `yaml:"trusted_proxies"`
	Admin          AdminConfig    `yaml:"admin"`
}

// AdminConfig controls access to the /_relay/admin/* management endpoints.
type AdminConfig struct {
	// AllowedCIDRs is the list of IP ranges that may call admin endpoints.
	// Defaults to loopback only (127.0.0.0/8 and ::1/128) when empty.
	AllowedCIDRs []string `yaml:"allowed_cidrs"`
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
}

type TimeoutsConfig struct {
	Read         time.Duration `yaml:"read"`
	Write        time.Duration `yaml:"write"`
	Idle         time.Duration `yaml:"idle"`
	ReadTimeout  time.Duration `yaml:"-"`
	WriteTimeout time.Duration `yaml:"-"`
	IdleTimeout  time.Duration `yaml:"-"`
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
}

type MatchConfig struct {
	Path       string   `yaml:"path"`
	PathPrefix string   `yaml:"path_prefix"`
	Methods    []string `yaml:"methods"`
	Hosts      []string `yaml:"hosts"`
}

type BackendConfig struct {
	Name           string               `yaml:"name"`
	Strategy       string               `yaml:"strategy"`
	HealthCheck    HealthCheckConfig    `yaml:"health_check"`
	CircuitBreaker CircuitBreakerConfig `yaml:"circuit_breaker"`
	Retry          RetryConfig          `yaml:"retry"`
	Instances      []InstanceConfig     `yaml:"instances"`
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
}

type MiddlewareConfig struct {
	Name    string                   `yaml:"name"`
	Type    string                   `yaml:"type"`
	Enabled bool                     `yaml:"enabled"`
	Config  MiddlewareSettingsConfig `yaml:"config"`
}

type MiddlewareSettingsConfig struct {
	SecretEnv          string            `yaml:"secret_env"`
	ResolvedSecret     string            `yaml:"-"`
	Header             string            `yaml:"header"`
	ClaimsToHeaders    map[string]string `yaml:"claims_to_headers"`
	// JWT algorithm selection: hs256 (default), rs256.
	Algorithm    string        `yaml:"algorithm"`
	// PublicKeyFile is the path to a PEM-encoded RSA public key for rs256.
	PublicKeyFile string       `yaml:"public_key_file"`
	// JWKSUrl is a JWKS endpoint URL for rs256 key discovery.
	JWKSUrl      string        `yaml:"jwks_url"`
	// JWKSCacheTTL is how long JWKS keys are cached. Defaults to 5m when zero.
	JWKSCacheTTL time.Duration `yaml:"jwks_cache_ttl"`
	MaxBytes           int64             `yaml:"max_bytes"`
	Allow              []string          `yaml:"allow"`
	Deny               []string          `yaml:"deny"`
	Strategy           string            `yaml:"strategy"`
	Limit              int               `yaml:"limit"`
	Window             time.Duration     `yaml:"window"`
	By                 string            `yaml:"by"`
	AllowedOrigins     []string          `yaml:"allowed_origins"`
	AllowedMethods     []string          `yaml:"allowed_methods"`
	AllowedHeaders     []string          `yaml:"allowed_headers"`
	AllowCredentials   bool              `yaml:"allow_credentials"`
	// JWTLogFailures emits structured Warn logs on JWT rejection (missing header, parse/signature/claims).
	// Does not log the raw token or secret; payload inspection lists claim keys and exp only.
	JWTLogFailures bool `yaml:"jwt_log_failures"`
	// Header middleware fields
	RequestSet  map[string]string `yaml:"request_set"`
	RequestDel  []string          `yaml:"request_del"`
	ResponseSet map[string]string `yaml:"response_set"`
	ResponseDel []string          `yaml:"response_del"`
}

type ObservabilityConfig struct {
	Dashboard  DashboardConfig  `yaml:"dashboard"`
	Logs       LogsConfig       `yaml:"logs"`
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
