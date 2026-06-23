SHELL := /bin/sh

VERSION    := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS    := -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)

.PHONY: dev test build lint release docker load loadtest

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

lint:
	golangci-lint run

release:
	goreleaser release

docker:
	docker build -t algoryn/relay:local .
