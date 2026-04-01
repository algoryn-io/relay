package config

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}

	var cfg Config
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode config %q: %w", path, err)
	}

	cfg.normalizeAliases()

	return &cfg, nil
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
	if c.Match.Path == "" {
		c.Match.Path = c.Match.PathPrefix
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
}

func (c *ObservabilityConfig) normalizeAliases() {
	if c.Dashboard.Path == "" && c.Dashboard.Enabled {
		c.Dashboard.Path = "/dashboard"
	}
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
		Name        string      `yaml:"name"`
		ID          string      `yaml:"id"`
		Match       MatchConfig `yaml:"match"`
		Middleware  []string    `yaml:"middleware"`
		Middlewares []string    `yaml:"middlewares"`
		Backend     string      `yaml:"backend"`
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

	return nil
}

func (c *MatchConfig) UnmarshalYAML(node *yaml.Node) error {
	type rawMatch struct {
		Path       string   `yaml:"path"`
		PathPrefix string   `yaml:"path_prefix"`
		Methods    []string `yaml:"methods"`
		Hosts      []string `yaml:"hosts"`
	}

	var raw rawMatch
	if err := node.Decode(&raw); err != nil {
		return err
	}

	c.Path = raw.Path
	c.PathPrefix = raw.PathPrefix
	c.Methods = raw.Methods
	c.Hosts = raw.Hosts

	return nil
}

func (c *BackendConfig) UnmarshalYAML(node *yaml.Node) error {
	type rawBackend struct {
		Name        string            `yaml:"name"`
		Strategy    string            `yaml:"strategy"`
		HealthCheck HealthCheckConfig `yaml:"health_check"`
		Healthcheck HealthCheckConfig `yaml:"healthcheck"`
		Instances   []InstanceConfig  `yaml:"instances"`
	}

	var raw rawBackend
	if err := node.Decode(&raw); err != nil {
		return err
	}

	c.Name = raw.Name
	c.Strategy = raw.Strategy
	c.HealthCheck = raw.HealthCheck
	if c.HealthCheck == (HealthCheckConfig{}) {
		c.HealthCheck = raw.Healthcheck
	}
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
