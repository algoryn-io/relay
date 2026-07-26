package config

import (
	"os"
	"path/filepath"
	"testing"
)

// writeFiles writes each name→content pair into a shared temp dir and returns
// the dir path. Used to compose multi-file include scenarios.
func writeFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		full := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("MkdirAll(%s) error = %v", name, err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", name, err)
		}
	}
	return dir
}

func TestLoadMergesIncludedFiles(t *testing.T) {
	t.Parallel()

	dir := writeFiles(t, map[string]string{
		"main.yaml": `
include:
  - routes/orders.yaml
  - routes/users.yaml
listener:
  http:
    port: 8080
  timeouts:
    read: 30s
    write: 30s
    idle: 60s
`,
		"routes/orders.yaml": `
routes:
  - name: orders
    match: { path: /orders, methods: [GET] }
    backend: orders-backend
backends:
  - name: orders-backend
    strategy: round_robin
    instances:
      - url: http://localhost:9001
`,
		"routes/users.yaml": `
routes:
  - name: users
    match: { path: /users, methods: [GET] }
    backend: users-backend
backends:
  - name: users-backend
    strategy: round_robin
    instances:
      - url: http://localhost:9002
`,
	})
	cfg, err := Load(filepath.Join(dir, "main.yaml"))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if len(cfg.Routes) != 2 {
		t.Fatalf("routes = %d, want 2", len(cfg.Routes))
	}
	if len(cfg.Backends) != 2 {
		t.Fatalf("backends = %d, want 2", len(cfg.Backends))
	}
	if cfg.Listener.HTTP.Port != 8080 {
		t.Fatalf("listener port = %d, want 8080 (from main)", cfg.Listener.HTTP.Port)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("merged config invalid: %v", err)
	}
}

func TestLoadIncludeCycleIsSafe(t *testing.T) {
	t.Parallel()

	dir := writeFiles(t, map[string]string{
		"a.yaml": `
include: [b.yaml]
listener:
  http:
    port: 8080
  timeouts:
    read: 30s
    write: 30s
    idle: 60s
routes:
  - name: a
    match: { path: /a, methods: [GET] }
    backend: a-backend
backends:
  - name: a-backend
    strategy: round_robin
    instances:
      - url: http://localhost:9001
`,
		"b.yaml": `
include: [a.yaml]
routes:
  - name: b
    match: { path: /b, methods: [GET] }
    backend: b-backend
backends:
  - name: b-backend
    strategy: round_robin
    instances:
      - url: http://localhost:9002
`,
	})

	cfg, err := Load(filepath.Join(dir, "a.yaml"))
	if err != nil {
		t.Fatalf("Load() error = %v (cycle must be handled, not fatal)", err)
	}
	// Each file merged once: routes a and b, no duplicates.
	if len(cfg.Routes) != 2 {
		t.Fatalf("routes = %d, want 2 (each file included once)", len(cfg.Routes))
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config invalid: %v", err)
	}
}

func TestLoadDiamondIncludeMergesBaseOnce(t *testing.T) {
	t.Parallel()

	dir := writeFiles(t, map[string]string{
		"main.yaml": `
include: [left.yaml, right.yaml]
listener:
  http:
    port: 8080
  timeouts:
    read: 30s
    write: 30s
    idle: 60s
`,
		"left.yaml":  "include: [base.yaml]\n",
		"right.yaml": "include: [base.yaml]\n",
		"base.yaml": `
routes:
  - name: base
    match: { path: /base, methods: [GET] }
    backend: base-backend
backends:
  - name: base-backend
    strategy: round_robin
    instances:
      - url: http://localhost:9003
`,
	})

	cfg, err := Load(filepath.Join(dir, "main.yaml"))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	// base.yaml is included via both left and right but merged only once.
	if len(cfg.Routes) != 1 {
		t.Fatalf("routes = %d, want 1 (base merged once despite diamond)", len(cfg.Routes))
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config invalid: %v", err)
	}
}
