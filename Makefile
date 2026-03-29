SHELL := /bin/sh

.PHONY: dev test build lint release docker

dev:
	go run ./cmd/relay -config config/example.yaml

test:
	go test ./...

build:
	cd dashboard && npm ci && npm run build
	go build -o bin/relay ./cmd/relay

lint:
	golangci-lint run

release:
	goreleaser release

docker:
	docker build -t algoryn/relay:local .
