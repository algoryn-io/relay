package config

import (
	"fmt"
	"os"
	"strings"
)

// ResolveSecretFiles reads secrets from mounted files into their resolved
// targets. This is the Kubernetes-native pattern: mount a Secret as a volume and
// point Relay at the file path instead of exposing the value as an environment
// variable. File contents are trimmed of surrounding whitespace.
//
// It is applied after ResolveEnv, and only fills a target that is still empty, so
// the corresponding *_env source wins when both are configured. readFile
// defaults to os.ReadFile when nil (overridable in tests).
func (c *Config) ResolveSecretFiles(readFile func(string) ([]byte, error)) error {
	if c == nil {
		return errNilConfig
	}
	if readFile == nil {
		readFile = os.ReadFile
	}

	read := func(field, path string) (string, error) {
		data, err := readFile(path)
		if err != nil {
			return "", fmt.Errorf("%s: read secret file %q: %w", field, path, err)
		}
		value := strings.TrimSpace(string(data))
		if value == "" {
			return "", fmt.Errorf("%s: secret file %q is empty", field, path)
		}
		return value, nil
	}

	// Admin bearer token.
	if path := strings.TrimSpace(c.Listener.Admin.TokenFile); path != "" && c.Listener.Admin.ResolvedToken == "" {
		v, err := read("listener.admin.token_file", path)
		if err != nil {
			return err
		}
		c.Listener.Admin.ResolvedToken = v
	}

	for i := range c.Middleware {
		mw := &c.Middleware[i]
		cfg := &mw.Config
		prefix := fmt.Sprintf("middleware[%d].config", i)

		if path := strings.TrimSpace(cfg.SecretFile); path != "" && cfg.ResolvedSecret == "" {
			v, err := read(prefix+".secret_file", path)
			if err != nil {
				return err
			}
			cfg.ResolvedSecret = v
		}
		if path := strings.TrimSpace(cfg.ClientSecretFile); path != "" && cfg.ResolvedClientSecret == "" {
			v, err := read(prefix+".client_secret_file", path)
			if err != nil {
				return err
			}
			cfg.ResolvedClientSecret = v
		}
		if path := strings.TrimSpace(cfg.RedisURLFile); path != "" && strings.TrimSpace(cfg.RedisURL) == "" {
			v, err := read(prefix+".redis_url_file", path)
			if err != nil {
				return err
			}
			cfg.RedisURL = v
		}
	}

	return nil
}
