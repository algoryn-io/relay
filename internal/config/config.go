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
	HTTP     HTTPConfig     `yaml:"http"`
	HTTPS    HTTPSConfig    `yaml:"https"`
	TLS      TLSConfig      `yaml:"tls"`
	Timeouts TimeoutsConfig `yaml:"timeouts"`
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
	Name        string      `yaml:"name"`
	ID          string      `yaml:"id"`
	Match       MatchConfig `yaml:"match"`
	Middleware  []string    `yaml:"middleware"`
	Middlewares []string    `yaml:"-"`
	Backend     string      `yaml:"backend"`
}

type MatchConfig struct {
	Path       string   `yaml:"path"`
	PathPrefix string   `yaml:"path_prefix"`
	Methods    []string `yaml:"methods"`
	Hosts      []string `yaml:"hosts"`
}

type BackendConfig struct {
	Name        string            `yaml:"name"`
	Strategy    string            `yaml:"strategy"`
	HealthCheck HealthCheckConfig `yaml:"health_check"`
	Instances   []InstanceConfig  `yaml:"instances"`
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
	SecretEnv        string        `yaml:"secret_env"`
	ResolvedSecret   string        `yaml:"-"`
	Header           string        `yaml:"header"`
	MaxBytes         int64         `yaml:"max_bytes"`
	Strategy         string        `yaml:"strategy"`
	Limit            int           `yaml:"limit"`
	Window           time.Duration `yaml:"window"`
	By               string        `yaml:"by"`
	AllowedOrigins   []string      `yaml:"allowed_origins"`
	AllowedMethods   []string      `yaml:"allowed_methods"`
	AllowedHeaders   []string      `yaml:"allowed_headers"`
	AllowCredentials bool          `yaml:"allow_credentials"`
}

type ObservabilityConfig struct {
	Dashboard DashboardConfig `yaml:"dashboard"`
	Logs      LogsConfig      `yaml:"logs"`
	Metrics   MetricsConfig   `yaml:"metrics"`
}

type DashboardConfig struct {
	Enabled bool   `yaml:"enabled"`
	Port    int    `yaml:"port"`
	Path    string `yaml:"path"`
}

type LogsConfig struct {
	Level      string `yaml:"level"`
	Directory  string `yaml:"directory"`
	MaxSizeMB  int    `yaml:"max_size_mb"`
	MaxBackups int    `yaml:"max_backups"`
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
