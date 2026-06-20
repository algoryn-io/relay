SHELL := /bin/sh

VERSION    := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS    := -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)

.PHONY: dev test build lint release docker

dev:
	go run ./cmd/relay -config config/example.yaml

test:
	go test ./...

build:
	cd dashboard && npm ci && npm run build
	go build -ldflags "$(LDFLAGS)" -o bin/relay ./cmd/relay

lint:
	golangci-lint run

release:
	goreleaser release

docker:
	docker build -t algoryn/relay:local .
