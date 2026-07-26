[![CI](https://github.com/algoryn-io/relay/actions/workflows/ci.yml/badge.svg)](https://github.com/algoryn-io/relay/actions/workflows/ci.yml)
![Go Version](https://img.shields.io/badge/go-1.25-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Algoryn Fabric](https://img.shields.io/badge/algoryn-fabric-purple)

# Relay

## TL;DR
```bash
cp config/example.yaml my-config.yaml
RELAY_CONFIG=./my-config.yaml go run ./cmd/relay
```
Relay is a lightweight, self-hosted API Gateway written in Go: a single stateless
binary driven by one config file, stdlib-first with minimal dependencies. It runs
the same way on a small VPS or as a scaled fleet in Kubernetes — no control plane,
no extra infrastructure.

## Features

- **Routing** — match by `path` / `path_prefix`, `method`, `hosts`, `headers`, and
  `query`; most-specific-wins with catch-all fallback (virtual hosting, canary,
  API versioning).
- **Load balancing & upstreams** — `round_robin`, `least_connections`,
  `weighted_random`; active health checks; HTTP/1.1, TLS (h2 via ALPN) and
  cleartext HTTP/2 (`h2c`) backends for gRPC.
- **Resilience** — retries with backoff and a retry **budget**, circuit breaker,
  per-backend **bulkhead**, global concurrency cap, per-route timeouts.
- **Auth & security** — JWT (HS256/RS256/JWKS/**OIDC discovery**), API keys,
  **OAuth2 introspection** (RFC 7662), **external authorization** (`ext_authz`),
  IP filter, CORS, body limit, inbound/outbound **mTLS**, TLS hardening, edge
  header stripping.
- **Rate limiting & caching** — sliding-window rate limiting (in-memory or shared
  via **Redis**); response **cache** with `Cache-Control`/`Vary` awareness.
- **Observability** — structured `slog` logs, **Prometheus** metrics, **OpenTelemetry**
  tracing, `/_relay/health` + `/_relay/ready`, shipped Grafana dashboard and alert
  rules.
- **Operations** — hot config reload, config `include` composition, cert rotation
  without restart, admin REST API, secrets from env or files, graceful shutdown.
- **Packaging** — single binary, hardened container, Helm chart, systemd unit,
  signed releases (SBOM + cosign + SLSA provenance).

See the full [configuration reference](docs/configuration.md) and the
[deployment guide](docs/deployment.md).

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
curl -i http://localhost:8088/test
```

Adjust host, port, and path based on your config (the shipped `example.yaml`
listens on `8088`).

### Check metrics

```bash
curl -s http://localhost:8088/_relay/metrics | jq
```

### Example: API gateway with prefix routes

For a fuller example (health, `/storage`, `/verify`, `/v1/auth`, `/v1` prefixes, CORS, rate limits) see [`config/examples/api-gateway-prefix-routes.yaml`](config/examples/api-gateway-prefix-routes.yaml). Run it with:

```bash
./scripts/run-with-config.sh ./config/examples/api-gateway-prefix-routes.yaml
```

Or set `RELAY_CONFIG` to that path manually. The helper script lives at [`scripts/run-with-config.sh`](scripts/run-with-config.sh).

---

## Deployment

Relay is one stateless binary driven by one config file — the same build runs a
single-instance gateway on a VPS or a scaled fleet in Kubernetes. See the full
[deployment guide](docs/deployment.md). In short:

- **VPS / bare host** — a hardened [`systemd` unit](deploy/systemd/relay.service)
  or a production [`docker-compose`](deploy/docker-compose.prod.yaml); TLS via
  ACME/Let's Encrypt (`tls.mode: auto`).
- **Kubernetes** — the [Helm chart](deploy/helm/relay) (Deployment, Service,
  ConfigMap, optional HPA/PDB/ServiceMonitor, probes, non-root read-only pod):

  ```bash
  helm install relay ./deploy/helm/relay --set replicaCount=2
  ```

- **Gateway API** — put Relay behind a cluster `Gateway`/`HTTPRoute`; examples in
  [`deploy/gateway-api`](deploy/gateway-api).

Scale horizontally by running multiple replicas behind the Service; point the
`rate_limit` middleware at Redis (`store: redis`) for a shared limit. Metrics are
loopback-only unless you allow a scrape range via
`observability.prometheus.allowed_cidrs`.

---

## Route matching

- `match.path`: **exact** path (e.g. `/health`).
- `match.path_prefix`: **prefix** match: the request path must equal the prefix or continue with `/` (e.g. `/v1` matches `/v1` and `/v1/students`, not `/v10`). If several prefixes match, the **longest** wins. `path` and `path_prefix` are mutually exclusive.
- `match.hosts`: restrict a route to one or more `Host` values (port-stripped, case-insensitive). Empty means any host. Two routes can share the same path with different hosts (virtual hosting / multi-tenant).
- `match.headers`: map of request header → exact value. The route only matches when every listed header equals the given value (useful for canary routing and header-based API versioning).
- `match.query`: map of query parameter → exact value. Same semantics as `headers`.

When several routes share a path, the **most specific** wins: a route constrained by host/header/query is preferred over a catch-all, and the router falls back to the catch-all when the specific route's predicates do not match.

```yaml
routes:
  - name: canary
    match:
      path_prefix: /api
      methods: [GET, POST]
      hosts: [api.example.com]
      headers:
        X-Canary: "true"
    backend: api-canary
  - name: stable
    match:
      path_prefix: /api
      methods: [GET, POST]
      hosts: [api.example.com]
    backend: api-stable
```

## Configuration Overview

```yaml
listener:
  http:
    port: 8088
  timeouts:
    read: 30s
    write: 30s
    idle: 60s
    read_header: 10s      # header-read timeout (Slowloris mitigation)
    websocket_idle: 5m    # close idle proxied WebSocket tunnels (0 = off)
  trusted_proxies: []     # CIDRs/IPs of proxies allowed to set X-Forwarded-For
  strip_request_headers: # extra inbound identity headers to drop at the edge
    - X-User-Id
    - X-Roles
  max_concurrent_requests: 0  # global in-flight cap (0 = unlimited); fast 503 over it
  max_connections_per_ip: 0   # real TCP peer cap (0 = off); never trusts forwarded headers
  https:
    port: 8443
    tls:
      mode: manual          # or "auto" (ACME/Let's Encrypt)
      cert_file: ./tls/server.crt
      key_file: ./tls/server.key
      min_version: "1.3"    # "1.2" (default, hardened ciphers) or "1.3"
      client_ca_file: ./tls/client-ca.crt  # set to require inbound mTLS
      client_auth: require  # require | verify_if_given | request
  admin:
    allowed_cidrs: ["127.0.0.0/8"]
    token_env: RELAY_ADMIN_TOKEN  # optional bearer token on top of the allowlist

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
    protocol: http1        # or "h2c" for cleartext HTTP/2 (gRPC) backends
    health_check:
      interval: 10s
      timeout: 2s
      path: /health
    retry:
      attempts: 3
      on: [5xx, network_error]
      budget_ratio: 0.2    # cap retries at ~20% of traffic (anti retry-storm)
      budget_tokens: 100   # burst allowance
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
      memory_max_buckets: 100000
      memory_bucket_ttl: 5m
      memory_cleanup_interval: 1m

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

```

---

## Middleware

### JWT (`type: jwt`)

- Configurable header (`Authorization` by default)
- Supports `Bearer <token>`
- HS256 (shared secret via `secret_env`) or RS256 (static `public_key_file` or a
  JWKS endpoint via `jwks_url`, which must be `https`)
- Validates signature and expiration; optionally enforces `issuer` and `audience`
  so tokens minted for another issuer/audience are rejected

### Rate Limit (`type: rate_limit`)

- Supported strategy: `sliding_window`
- Supported keys: `ip`, `route`, `api_key`
- The in-memory store defaults to 100,000 buckets, expires idle buckets, and
  uses bounded sharded LRU eviction under high-cardinality traffic.
- Tune `memory_max_buckets`, `memory_bucket_ttl` (at least the rate-limit
  window), and `memory_cleanup_interval`; Redis settings are unaffected.

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

### API key (`type: api_key`)

- Reads the key from a header (`key_header`) or query parameter (`key_query`)
- Valid keys come from an env var (`keys_env`) or a file (`keys_file`); comparison
  is constant-time
- Optionally maps the matched key to an outbound header (`key_to_header`)

```yaml
- name: api-keys
  type: api_key
  config:
    key_header: X-API-Key
    keys_env: RELAY_API_KEYS      # comma/space/newline-separated
    key_to_header: X-Client-Id
```

### Header (`type: header`)

- Sets or deletes request headers before proxying (`request_set` / `request_del`)
  and response headers (`response_set` / `response_del`)

```yaml
- name: inject-headers
  type: header
  config:
    request_set: { X-Env: prod }
    response_del: [Server]
```

### JWT via OIDC discovery (`type: jwt`, `algorithm: rs256`)

- Set `oidc_issuer: https://issuer.example.com` instead of `jwks_url`
- Relay fetches `<issuer>/.well-known/openid-configuration` and derives the
  `jwks_uri` automatically (keys are cached like the direct JWKS path)
- `iss` is enforced against the discovered issuer by default

### OAuth2 token introspection (`type: oauth2`)

- Verifies **opaque** access tokens against an RFC 7662 introspection endpoint
- HTTP Basic client auth (`client_id` + `client_secret_env`), `https` required
- Optional `required_scopes`; positive results cached up to `cache_ttl` (bounded
  by the token's own expiry). Fails closed if the endpoint is unreachable
- Injects `X-Authenticated-Sub` and `X-Token-Scope` for the backend

```yaml
- name: introspect
  type: oauth2
  config:
    introspection_url: https://idp.example.com/oauth2/introspect
    client_id: relay
    client_secret_env: INTROSPECTION_SECRET
    required_scopes: [read]
    cache_ttl: 60s
```

### External authorization (`type: ext_authz`)

- Delegates the allow/deny decision to an external HTTP service (Envoy
  `ext_authz` style). The probe forwards method, URI, host, client IP and any
  `forward_headers`
- `2xx` allows (optionally grafting `copy_headers` from the response onto the
  upstream request); `401`/`403` deny; other/errors follow `fail_open`

```yaml
- name: opa
  type: ext_authz
  config:
    authz_url: http://opa:8181/v1/data/http/authz
    forward_headers: [Authorization]
    copy_headers: [X-User-Id]
    fail_open: false
```

### Response cache (`type: cache`)

- Caches idempotent responses (`GET`/`HEAD` by default) in a bounded in-memory
  LRU with per-entry TTL
- Honors request/response `Cache-Control` (`no-store`, `no-cache`, `private`,
  `max-age`/`s-maxage`), skips `Set-Cookie` responses, honors the origin's `Vary`,
  and streams (uncached) bodies larger than `max_object_bytes`
- **Safe for authenticated routes:** a request with `Authorization`/`Cookie` is
  only cached/served when the response is explicitly `public`/`s-maxage`, so one
  user's response is never returned to another (RFC 7234)
- Adds `X-Cache: HIT|MISS|BYPASS` and an `Age` header; `vary` folds request
  headers into the cache key

```yaml
- name: page-cache
  type: cache
  config:
    ttl: 30s
    methods: [GET, HEAD]
    max_object_bytes: 1048576
    max_entries: 5000
    vary: [Accept-Encoding]
```

---

## gRPC / HTTP-2 (h2c)

- The plaintext listener accepts **cleartext HTTP/2 (h2c)** alongside HTTP/1.1, so
  gRPC (and other HTTP/2) clients can connect without TLS. HTTPS listeners already
  negotiate HTTP/2 via ALPN.
- Set `protocol: h2c` on a backend to forward to a **cleartext HTTP/2 upstream**
  (typical for gRPC services behind a mesh). Responses stream end-to-end
  (immediate flush, no retry buffering) so bidirectional streaming works.
- `protocol: http1` (default) keeps HTTP/1.1 with HTTP/2 via ALPN for `https`
  backends. `h2c` cannot be combined with backend `tls` (it is cleartext).

## Retry budget

Retries are capped as a fraction of request volume so a failing backend cannot
amplify its own load (a "retry storm"). It is a token bucket: each completed
request replenishes `budget_ratio` tokens (up to `budget_tokens`), and each retry
spends one. When empty, retries are suppressed and
`relay_retry_budget_exhausted_total` increments.

```yaml
backends:
  - name: api
    retry:
      attempts: 3
      on: [5xx, network_error]
      budget_ratio: 0.2    # sustained retries ≤ ~20% of traffic (0 = unlimited)
      budget_tokens: 100   # initial burst allowance
```

## Secrets from files

Every secret that accepts a `*_env` source also accepts a `*_file` source that
reads the value from a mounted file (the Kubernetes Secret-volume pattern),
trimmed of surrounding whitespace. `*_env` wins when both are set.

- `middleware.config.secret_file` (JWT HS256), `client_secret_file` (oauth2),
  `redis_url_file` (rate limit)
- `listener.admin.token_file` (admin bearer token)

## Config composition (`include`)

Split a large config across files. `include` merges the `routes`, `backends` and
`middleware` from each listed file (relative to the including file, or absolute)
into the top level. Includes are loaded **once** — shared bases and cycles are
handled safely — and duplicate names across files are caught by validation.

```yaml
# relay.yaml
include:
  - backends/payments.yaml
  - routes/public.yaml
listener:
  http:
    port: 8088
```

---

## Observability

### Health & readiness

- `GET /_relay/health` — liveness; always 200 while the process is up.
- `GET /_relay/ready` — readiness; 503 when backends exist but none has a healthy
  instance. Use it for Kubernetes readiness probes.

### Metrics

Endpoints (loopback-gated):

- `GET /_relay/metrics` — JSON snapshot
- `GET /_relay/metrics/prometheus` — Prometheus exposition

Includes per-route request/latency/status metrics plus resilience metrics:
`relay_upstream_duration_seconds` (by backend), `relay_retry_total`,
`relay_circuit_breaker_state`, `relay_bulkhead_in_flight`,
`relay_bulkhead_rejected_total`, and `relay_backend_healthy`.

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

## Versioning & stability

Relay follows [Semantic Versioning](https://semver.org/). Starting with `v1.0.0`:

- The **YAML configuration schema** and the **HTTP surface** (`/_relay/*`
  endpoints, error-response shape) are the public contract. Breaking changes to
  either happen only in a major release.
- New fields and middleware types are additive (minor releases); fixes are patch
  releases. Deprecations are documented in [`CHANGELOG.md`](CHANGELOG.md) before
  removal.
- Internal Go packages (`internal/...`) are not a public API.

Releases are built in CI and ship a checksummed SBOM, cosign signatures, and SLSA
build provenance — see [`SECURITY.md`](SECURITY.md) for verification.

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
