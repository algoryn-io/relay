package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	defaultMaxRequestBodyBytes            int64 = 10 << 20
	defaultRateLimitMemoryMaxBuckets            = 100_000
	defaultRateLimitMemoryCleanupInterval       = time.Minute
)

func Load(path string) (*Config, error) {
	cfg, _, err := LoadWithFiles(path)
	return cfg, err
}

// LoadWithFiles loads path and returns every canonical file path encountered,
// including the root and transitive includes. The file list is also returned
// on error so callers can watch a missing include and recover when it appears.
func LoadWithFiles(path string) (*Config, []string, error) {
	loaded := make(map[string]struct{})
	cfg, err := loadWithIncludes(path, loaded)
	files := make([]string, 0, len(loaded))
	for file := range loaded {
		files = append(files, file)
	}
	sort.Strings(files)
	return cfg, files, err
}

// loadWithIncludes loads a single config file and recursively merges any files
// it lists under `include`. The loaded set records absolute paths already merged
// so a file is included at most once — this makes includes idempotent and safe
// against cycles (a file that transitively includes itself) and diamonds (two
// files including a common base).
func loadWithIncludes(path string, loaded map[string]struct{}) (*Config, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve config path %q: %w", path, err)
	}
	abs = filepath.Clean(abs)
	if _, seen := loaded[abs]; seen {
		// Already merged via another include; contribute nothing further.
		return &Config{}, nil
	}
	loaded[abs] = struct{}{}

	// #nosec G304 -- path is the operator-selected root or an include resolved from it.
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", abs, err)
	}

	var cfg Config
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode config %q: %w", abs, err)
	}

	cfg.normalizeAliases()

	includes := cfg.Include
	cfg.Include = nil
	baseDir := filepath.Dir(abs)
	for _, inc := range includes {
		incPath := inc
		if !filepath.IsAbs(incPath) {
			incPath = filepath.Join(baseDir, incPath)
		}
		sub, err := loadWithIncludes(incPath, loaded)
		if err != nil {
			return nil, fmt.Errorf("include %q: %w", inc, err)
		}
		cfg.mergeIncluded(sub)
	}

	return &cfg, nil
}

// mergeIncluded appends the routes, backends and middleware contributed by an
// included config. Duplicate names across files are caught by validation.
func (c *Config) mergeIncluded(other *Config) {
	if other == nil {
		return
	}
	c.Routes = append(c.Routes, other.Routes...)
	c.Backends = append(c.Backends, other.Backends...)
	c.Middleware = append(c.Middleware, other.Middleware...)
}

func (c *Config) normalizeAliases() {
	if c == nil {
		return
	}

	c.Listener.normalizeAliases()

	for i := range c.Routes {
		c.Routes[i].normalizeAliases()
	}

	for i := range c.Middleware {
		c.Middleware[i].normalizeAliases()
	}

	c.Observability.normalizeAliases()
	c.Reload.normalizeAliases()
}

func (c *ListenerConfig) normalizeAliases() {
	if c.TLS.Mode != "" && c.HTTPS.TLS.Mode == "" {
		c.HTTPS.TLS = c.TLS
	}
	if c.TLS.Mode == "" && c.HTTPS.TLS.Mode != "" {
		c.TLS = c.HTTPS.TLS
	}
	c.Timeouts.normalizeAliases()
	if c.MaxRequestBodyBytes == 0 {
		c.MaxRequestBodyBytes = defaultMaxRequestBodyBytes
	}
}

func (c *TimeoutsConfig) normalizeAliases() {
	if c.Read == 0 {
		c.Read = c.ReadTimeout
	}
	if c.Write == 0 {
		c.Write = c.WriteTimeout
	}
	if c.Idle == 0 {
		c.Idle = c.IdleTimeout
	}

	c.ReadTimeout = c.Read
	c.WriteTimeout = c.Write
	c.IdleTimeout = c.Idle
}

func (c *RouteConfig) normalizeAliases() {
	if c.Name == "" {
		c.Name = c.ID
	}
	if len(c.Middleware) == 0 {
		c.Middleware = c.Middlewares
	}
	c.Middlewares = c.Middleware
}

func (c *MiddlewareConfig) normalizeAliases() {
	switch c.Type {
	case "ratelimit":
		c.Type = "rate_limit"
	}
	if c.Type == "rate_limit" {
		if c.Config.MemoryMaxBuckets == 0 {
			c.Config.MemoryMaxBuckets = defaultRateLimitMemoryMaxBuckets
		}
		if c.Config.MemoryBucketTTL == 0 {
			c.Config.MemoryBucketTTL = c.Config.Window
		}
		if c.Config.MemoryCleanupInterval == 0 {
			c.Config.MemoryCleanupInterval = defaultRateLimitMemoryCleanupInterval
		}
	}
}

func (c *ObservabilityConfig) normalizeAliases() {
	if c.Logs.Level == "" {
		c.Logs.Level = "info"
	}
	if c.Logs.Format == "" {
		c.Logs.Format = "json"
	}
}

func (c *ReloadConfig) normalizeAliases() {
	if !c.Watch && c.Enabled {
		c.Watch = c.Enabled
	}
}

func (c *TimeoutsConfig) UnmarshalYAML(node *yaml.Node) error {
	type rawTimeouts struct {
		Read         timeDuration `yaml:"read"`
		Write        timeDuration `yaml:"write"`
		Idle         timeDuration `yaml:"idle"`
		ReadTimeout  timeDuration `yaml:"read_timeout"`
		WriteTimeout timeDuration `yaml:"write_timeout"`
		IdleTimeout  timeDuration `yaml:"idle_timeout"`
	}

	var raw rawTimeouts
	if err := node.Decode(&raw); err != nil {
		return err
	}

	c.Read = raw.Read.Duration()
	c.Write = raw.Write.Duration()
	c.Idle = raw.Idle.Duration()
	c.ReadTimeout = raw.ReadTimeout.Duration()
	c.WriteTimeout = raw.WriteTimeout.Duration()
	c.IdleTimeout = raw.IdleTimeout.Duration()

	return nil
}

func (c *RouteConfig) UnmarshalYAML(node *yaml.Node) error {
	type rawRoute struct {
		Name              string            `yaml:"name"`
		ID                string            `yaml:"id"`
		Match             MatchConfig       `yaml:"match"`
		Middleware        []string          `yaml:"middleware"`
		Middlewares       []string          `yaml:"middlewares"`
		Backend           string            `yaml:"backend"`
		StripPrefix       string            `yaml:"strip_prefix"`
		Timeout           timeDuration      `yaml:"timeout"`
		MaxBodyBytes      int64             `yaml:"max_body_bytes"`
		Rewrite           RewriteRule       `yaml:"rewrite"`
		AddRequestHeaders map[string]string `yaml:"add_request_headers"`
	}

	var raw rawRoute
	if err := node.Decode(&raw); err != nil {
		return err
	}

	c.Name = raw.Name
	c.ID = raw.ID
	c.Match = raw.Match
	c.Middleware = raw.Middleware
	c.Middlewares = raw.Middlewares
	c.Backend = raw.Backend
	c.StripPrefix = raw.StripPrefix
	c.Timeout = raw.Timeout.Duration()
	c.MaxBodyBytes = raw.MaxBodyBytes
	c.Rewrite = raw.Rewrite
	c.AddRequestHeaders = raw.AddRequestHeaders

	return nil
}

func (c *MatchConfig) UnmarshalYAML(node *yaml.Node) error {
	type rawMatch struct {
		Path       string            `yaml:"path"`
		PathPrefix string            `yaml:"path_prefix"`
		Methods    []string          `yaml:"methods"`
		Hosts      []string          `yaml:"hosts"`
		Headers    map[string]string `yaml:"headers"`
		Query      map[string]string `yaml:"query"`
	}

	var raw rawMatch
	if err := node.Decode(&raw); err != nil {
		return err
	}

	c.Path = raw.Path
	c.PathPrefix = raw.PathPrefix
	c.Methods = raw.Methods
	c.Hosts = raw.Hosts
	c.Headers = raw.Headers
	c.Query = raw.Query

	return nil
}

func (c *BackendConfig) UnmarshalYAML(node *yaml.Node) error {
	type rawBackend struct {
		Name           string               `yaml:"name"`
		Protocol       string               `yaml:"protocol"`
		Strategy       string               `yaml:"strategy"`
		HealthCheck    HealthCheckConfig    `yaml:"health_check"`
		Healthcheck    HealthCheckConfig    `yaml:"healthcheck"`
		CircuitBreaker CircuitBreakerConfig `yaml:"circuit_breaker"`
		Retry          RetryConfig          `yaml:"retry"`
		TLS            BackendTLSConfig     `yaml:"tls"`
		Bulkhead       BulkheadConfig       `yaml:"bulkhead"`
		Instances      []InstanceConfig     `yaml:"instances"`
	}

	var raw rawBackend
	if err := node.Decode(&raw); err != nil {
		return err
	}

	c.Name = raw.Name
	c.Protocol = raw.Protocol
	c.Strategy = raw.Strategy
	c.HealthCheck = raw.HealthCheck
	if c.HealthCheck == (HealthCheckConfig{}) {
		c.HealthCheck = raw.Healthcheck
	}
	c.CircuitBreaker = raw.CircuitBreaker
	c.Retry = raw.Retry
	c.TLS = raw.TLS
	c.Bulkhead = raw.Bulkhead
	c.Instances = raw.Instances

	return nil
}

type timeDuration struct {
	value time.Duration
}

func (d *timeDuration) Duration() time.Duration {
	if d == nil {
		return 0
	}
	return d.value
}

func (d *timeDuration) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == 0 {
		d.value = 0
		return nil
	}

	var text string
	if err := node.Decode(&text); err != nil {
		return err
	}
	if text == "" {
		d.value = 0
		return nil
	}

	parsed, err := time.ParseDuration(text)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", text, err)
	}
	d.value = parsed
	return nil
}
