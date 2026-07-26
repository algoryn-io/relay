SHELL := /bin/sh

VERSION    := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS    := -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)

GOVULNCHECK_VERSION  := v1.1.4
GOLANGCI_LINT_VERSION := v2.12.2
TOOLS_BIN             := $(CURDIR)/bin

.PHONY: dev test build lint vuln tools install-govulncheck install-golangci-lint release docker load loadtest

dev:
	go run ./cmd/relay -config config/example.yaml

test:
	go test -race ./...

# In-process load smoke test (regression guard for the hot path).
load:
	go test ./internal/listener -run TestLoadSmoke -v

# Standalone load generator against a running gateway.
# Usage: make loadtest URL=http://localhost:8088/your-route C=50 D=10s
URL ?= http://localhost:8088/
C   ?= 50
D   ?= 10s
loadtest:
	go run ./scripts/loadtest -url $(URL) -c $(C) -d $(D)

build:
	cd dashboard && npm ci && npm run build
	go build -ldflags "$(LDFLAGS)" -o bin/relay ./cmd/relay

install-govulncheck:
	GOBIN="$(TOOLS_BIN)" go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

install-golangci-lint:
	GOBIN="$(TOOLS_BIN)" go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

tools: install-govulncheck install-golangci-lint

lint: install-golangci-lint
	"$(TOOLS_BIN)/golangci-lint" run

vuln: install-govulncheck
	"$(TOOLS_BIN)/govulncheck" ./...

release:
	goreleaser release

docker:
	docker build -t algoryn/relay:local .
