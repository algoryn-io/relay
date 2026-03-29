![Build Status](https://img.shields.io/badge/build-pending-lightgrey)
![Go Version](https://img.shields.io/badge/go-1.25-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Algoryn Fabric](https://img.shields.io/badge/algoryn-fabric-purple)

# Relay

**Your API traffic, under control.**

Relay is a lightweight, self-hosted API Gateway in the Algoryn Fabric ecosystem. It focuses on secure traffic ingress, backend routing, middleware enforcement, and operational visibility with a built-in dashboard.

## Quick Install

### Binary download

1. Download the latest release archive from the GitHub releases page.
2. Extract it and move `relay` into your `PATH`.
3. Run `relay` with your config file.

### Docker

```bash
docker run --rm -p 8088:8088 -v "$(pwd)/config:/app/config" algoryn/relay:latest
```

## Quickstart

1. Copy `config/example.yaml` and adjust backend URLs, JWT settings, and ports.
2. Start Relay:
   ```bash
   make dev
   ```
3. Send traffic through `http://localhost:8088` and open dashboard endpoints under `/dashboard`.

## Configuration

- Example config: `config/example.yaml`
- Full config reference: `docs/`

## Ecosystem Context

Relay is part of the Algoryn Fabric platform and is intended to interoperate with Fabric metrics, event streams, and service observability pipelines.
