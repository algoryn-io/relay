![Build Status](https://img.shields.io/badge/build-pending-lightgrey)
![Go Version](https://img.shields.io/badge/go-1.25-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Algoryn Fabric](https://img.shields.io/badge/algoryn-fabric-purple)

# Relay

## TL;DR
```bash
cp config/example.yaml my-config.yaml
RELAY_CONFIG=./my-config.yaml go run ./cmd/relay
```
Relay is a lightweight, self-hosted API Gateway written in Go, designed for small teams that need straightforward HTTP traffic control without extra infrastructure.

## Current Features

Relay currently includes:

- Route matching by `path` + `method`
- Reverse proxy with `net/http/httputil`
- Load balancing:
  - `round_robin`
  - `least_connections`
- Active backend health checks
- Precomputed per-route middleware pipeline:
  - JWT auth
  - Rate limit (sliding window)
  - Body limit (`max_bytes`)
  - IP filter (`allow`/`deny`, exact IP and CIDR)
  - CORS
- Basic observability:
  - Structured logging with `slog`
  - Access logs to file with size-based rotation
  - In-memory metrics
  - `GET /_relay/metrics`
- Single binary deployment
- Stdlib-first design with minimal dependencies

---

## Quickstart

### Requirements

- Go 1.25+
- A YAML config file (for example `config/example.yaml`)

### Run locally

```bash
go run ./cmd/relay
```

By default, Relay uses `config/example.yaml`.
You can override it with:

```bash
RELAY_CONFIG=./config/example.yaml go run ./cmd/relay
```

### Test a route

```bash
curl -i http://localhost:8080/test
```

Adjust host, port, and path based on your config.

### Check metrics

```bash
curl -s http://localhost:8080/_relay/metrics | jq
```

### Example: API gateway with prefix routes

For a fuller example (health, `/storage`, `/verify`, `/v1/auth`, `/v1` prefixes, CORS, rate limits) see [`config/examples/api-gateway-prefix-routes.yaml`](config/examples/api-gateway-prefix-routes.yaml). Run it with:

```bash
./scripts/run-with-config.sh ./config/examples/api-gateway-prefix-routes.yaml
```

Or set `RELAY_CONFIG` to that path manually. The helper script lives at [`scripts/run-with-config.sh`](scripts/run-with-config.sh).

---

## Path matching

- `match.path`: **exact** path (e.g. `/health`).
- `match.path_prefix`: **prefix** match: the request path must equal the prefix or continue with `/` (e.g. `/v1` matches `/v1` and `/v1/students`, not `/v10`). If several prefixes match, the **longest** wins. `path` and `path_prefix` are mutually exclusive.

## Configuration Overview

```yaml
listener:
  http:
    port: 8080
  timeouts:
    read: 30s
    write: 30s
    idle: 60s

routes:
  - name: test-route
    match:
      path: /test
      methods: [GET]
    backend: test-backend
    middleware: [jwt-auth, api-rate-limit]

backends:
  - name: test-backend
    strategy: round_robin
    health_check:
      interval: 10s
      timeout: 2s
      path: /health
    instances:
      - url: http://localhost:9001
      - url: http://localhost:9002

middleware:
  - name: jwt-auth
    type: jwt
    config:
      secret_env: JWT_SECRET
      header: Authorization

  - name: api-rate-limit
    type: rate_limit
    config:
      strategy: sliding_window
      limit: 100
      window: 1m
      by: ip

  - name: api-body-limit
    type: body_limit
    config:
      max_bytes: 1048576

  - name: admin-ip-filter
    type: ip_filter
    config:
      allow:
        - 192.168.1.0/24
        - 10.0.0.1
      deny:
        - 10.0.0.9

  - name: api-cors
    type: cors
    config:
      allowed_origins: ["http://localhost:3000"]
      allowed_methods: ["GET", "POST", "OPTIONS"]
      allowed_headers: ["Authorization", "Content-Type"]

observability:
  logs:
    level: info
    format: json
    file: ./logs/access.log
    max_size_mb: 10
  metrics:
    flush_interval: 30s

```

---

## Middleware

### JWT (`type: jwt`)

- Configurable header (`Authorization` by default)
- Supports `Bearer <token>`
- Validates HMAC signature and expiration

### Rate Limit (`type: rate_limit`)

- Supported strategy: `sliding_window`
- Supported keys: `ip`, `route`, `api_key`

### Body Limit (`type: body_limit`)

- Enforces real body size using `http.MaxBytesReader`
- Returns `413` when request body exceeds `max_bytes`

### IP Filter (`type: ip_filter`)

- Supports `allow` and/or `deny`
- Supports exact IP and CIDR entries
- Rule order: allow first, deny can override

### CORS (`type: cors`)

- Handles `OPTIONS` preflight
- Validates configured origins, methods, and headers

---

## Observability

### Metrics

Endpoint:

- `GET /_relay/metrics`

Includes:

- `total_requests`
- Per-route request and latency stats (avg, p95)
- Status code counters

### Access Logs

- Structured JSON logs with `slog`
- If `observability.logs.file` is empty: logs go to `stdout`
- If `file` is set: logs are written to file with simple size rotation:
  - On limit overflow, `<file>` is rotated to `<file>.1`
  - Relay keeps current log + one backup

---

## Error Response Contract

Relay uses a consistent JSON shape for error responses across listener, proxy, and middleware:

```json
{
  "error": "<code>",
  "status": "error"
}
```

---
## Example Use Case

Relay can sit in front of a backend like:

- Go API with JWT authentication
- PDF generation services
- Public verification endpoints

Example routing:

- `/verify` → public endpoint with rate limiting
- `/v1/*` → protected endpoints with JWT + CORS + body limit

Flow:

Client → Relay → Backend API

---

## Architecture (Simple Flow)

Request flow:

1. `listener` receives request
2. `router` matches route by path + method
3. Precomputed route middleware pipeline executes
4. `proxy` selects backend using LB + health state
5. Request is forwarded upstream
6. Logging and metrics are recorded

---

## Short Roadmap

- More end-to-end integration tests for combined middleware scenarios
- Stronger hot-reload behavior for runtime config
- Operational health endpoint (`/_relay/health`)
- Better config validation DX (clearer defaults and messages)

---

## Development

Run tests:

```bash
go test ./...
```

Format code:

```bash
go fmt ./...
```

---

## License

MIT (see `LICENSE`).
