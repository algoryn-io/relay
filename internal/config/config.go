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
	Port int `yaml:"port"`
}

type TLSConfig struct {
	Mode     string `yaml:"mode"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

type TimeoutsConfig struct {
	ReadTimeout   time.Duration `yaml:"read_timeout"`
	WriteTimeout  time.Duration `yaml:"write_timeout"`
	IdleTimeout   time.Duration `yaml:"idle_timeout"`
	HeaderTimeout time.Duration `yaml:"header_timeout"`
}

type RouteConfig struct {
	ID          string          `yaml:"id"`
	Match       MatchConfig     `yaml:"match"`
	Backend     string          `yaml:"backend"`
	Middlewares []string        `yaml:"middlewares"`
	Thresholds  ThresholdConfig `yaml:"thresholds"`
}

type MatchConfig struct {
	PathPrefix string   `yaml:"path_prefix"`
	Methods    []string `yaml:"methods"`
	Hosts      []string `yaml:"hosts"`
}

type BackendConfig struct {
	Name        string            `yaml:"name"`
	Strategy    string            `yaml:"strategy"`
	HealthCheck HealthCheckConfig `yaml:"healthcheck"`
	Instances   []InstanceConfig  `yaml:"instances"`
}

type HealthCheckConfig struct {
	Path     string        `yaml:"path"`
	Interval time.Duration `yaml:"interval"`
	Timeout  time.Duration `yaml:"timeout"`
}

type InstanceConfig struct {
	ID  string `yaml:"id"`
	URL string `yaml:"url"`
}

type MiddlewareConfig struct {
	Name      string         `yaml:"name"`
	Type      string         `yaml:"type"`
	Enabled   bool           `yaml:"enabled"`
	RawConfig map[string]any `yaml:"config"`
}

type ObservabilityConfig struct {
	Dashboard DashboardConfig `yaml:"dashboard"`
	Logs      LogsConfig      `yaml:"logs"`
	Metrics   MetricsConfig   `yaml:"metrics"`
}

type DashboardConfig struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
}

type LogsConfig struct {
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
	Enabled bool `yaml:"enabled"`
}

type ThresholdConfig struct {
	ErrorRatePct float64 `yaml:"error_rate_pct"`
	P99Ms        int     `yaml:"p99_ms"`
}

func Load(path string) (*Config, error) {
	_ = path
	// TODO: implement relay YAML loading and decoding with gopkg.in/yaml.v3.
	return nil, nil
}

func (c *Config) Provider() any {
	_ = c
	// TODO: implement config provider adapter for Algoryn Fabric.
	return nil
}
