package config

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzLoad exercises the config decode path (YAML decoding plus the custom
// UnmarshalYAML implementations and alias normalization) against arbitrary input.
// The contract is that parsing never panics: malformed input must return an
// error, not crash. When a document does parse, Validate and BuildRuntime must
// also be panic-free.
func FuzzLoad(f *testing.F) {
	seeds := []string{
		"",
		"listener:\n  http:\n    port: 8080\n",
		"routes:\n  - name: r\n    match:\n      path: /x\n      methods: [GET]\n    backend: b\n",
		"backends:\n  - name: b\n    strategy: round_robin\n    retry:\n      attempts: 3\n      on: [5xx]\n    instances:\n      - url: http://localhost:9001\n",
		"listener:\n  timeouts:\n    read: 30s\n  admin:\n    token_file: /tmp/x\n",
		"include: [a.yaml]\n",
		"middleware:\n  - name: m\n    type: cache\n    config:\n      ttl: 30s\n",
		": : :\n\t- bad",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		path := filepath.Join(dir, "relay.yaml")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Skip()
		}

		cfg, err := Load(path)
		if err != nil {
			return // malformed input rejected cleanly — the expected outcome
		}
		if cfg == nil {
			t.Fatal("Load returned nil config and nil error")
		}
		// A parseable config must validate and build without panicking (errors are
		// acceptable; panics are not).
		if err := cfg.Validate(); err != nil {
			return
		}
		if _, err := BuildRuntime(cfg); err != nil {
			return
		}
	})
}
