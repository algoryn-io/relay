# Changelog

All notable changes to Relay are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project aims to follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Removed (breaking, pre-1.0)
- Removed the unserved React dashboard and its Node build/release stages.
- Removed the inert `observability.dashboard`, top-level `storage`, and
  `observability.metrics.flush_interval` configuration fields. The strict
  decoder now rejects them; delete these blocks before upgrading. The shipped
  Grafana dashboard, Prometheus endpoint, alert rules, and Helm integrations
  remain supported.

### Security
- Response cache no longer stores or serves a response to an authenticated request
  (`Authorization`/`Cookie`) unless the origin marks it `public`/`s-maxage`, and it
  now honors the origin's `Vary` header — preventing one user's response from being
  cached and returned to another (RFC 7234 §3.2).
- Client-IP resolution walks `X-Forwarded-For` right-to-left, skipping trusted
  proxy hops, instead of trusting the (client-controlled) left-most entry. This
  closes IP spoofing that could bypass `ip_filter` and `by: ip` rate limiting.
- `ext_authz` strips `copy_headers` from the inbound request before applying the
  authorizer's values, so a client cannot spoof an authorizer-resolved identity
  header when the authorizer allows the request without setting it.
- `X-Token-Scope` is added to the always-stripped edge identity headers.

### Added (supply chain & quality)
- Release pipeline in CI (`.github/workflows/release.yml`) running GoReleaser on
  `v*` tags, plus **SLSA build provenance** attestations for the release binaries
  and checksums (verifiable with `gh attestation verify`), on top of the existing
  SBOM and cosign signatures.
- Fuzz tests for the config parser (`FuzzLoad`) and the route matcher
  (`FuzzMatch`), and a CI `fuzz` job that runs each target for 60s.
- Benchmarks for the routing hot path and the config validate/build path, plus a
  CI `bench` job that runs them.

### Fixed
- Backend `retry`, `tls` and `bulkhead` blocks were silently dropped when a
  backend was configured via YAML (they were missing from the decoder's internal
  struct), so per-backend retries, outbound mTLS and the bulkhead concurrency
  limit did nothing when set in a config file. They are now parsed correctly.

### Added
- DNS backend discovery (`discovery.dns`): resolve A/AAAA/SRV records with TTL-aware
  refresh and atomic instance-pool updates. Kubernetes Service DNS works through
  ordinary cluster DNS; there is no Kubernetes Endpoints or Consul API client.
- Per-route backend failover (`failover.secondary` / `failover.backends`): when the
  primary backend cannot serve, Relay tries ordered secondary backends.
- Distributed response cache (`type: cache`, `store: redis`): shared Redis backend
  with TTL, Vary-aware keys, object size limits, `PURGE` invalidation, configurable
  `fail_open` on Redis errors, and the existing in-memory LRU as the default.
- Observability artifacts: a Grafana dashboard (RED signals plus upstream latency,
  backend health, retries/retry-budget, circuit-breaker state and bulkhead) and
  Prometheus alerting rules (error rate, p99 latency, backend health, open
  circuits, bulkhead rejections, retry-budget exhaustion, target down). The Helm
  chart can ship both (`metrics.dashboards.enabled`, `metrics.prometheusRule.enabled`).
- Deployment: an official Helm chart (`deploy/helm/relay`) with Deployment,
  Service, ConfigMap, optional HPA/PodDisruptionBudget/ServiceMonitor, health and
  readiness probes and a hardened (non-root, read-only) pod; Gateway API example
  manifests (`deploy/gateway-api`); a hardened systemd unit and a production
  docker-compose (`deploy/`); and a deployment guide (`docs/deployment.md`).
- `observability.prometheus.allowed_cidrs` allows scraping the metrics/Prometheus
  endpoints from configured source ranges (checked against the real TCP peer),
  keeping them loopback-only by default. Required for an in-cluster ServiceMonitor.
- gRPC / HTTP-2: the plaintext listener accepts cleartext HTTP/2 (h2c) alongside
  HTTP/1.1, and backends accept `protocol: h2c` to forward to cleartext HTTP/2
  upstreams with end-to-end streaming (no retry buffering).
- Retry budget: per-backend `retry.budget_ratio` / `retry.budget_tokens` cap
  retries as a fraction of traffic (token bucket) to prevent retry storms;
  suppressed retries increment `relay_retry_budget_exhausted_total`.
- File-based secrets: `secret_file`, `client_secret_file`, `redis_url_file` and
  `listener.admin.token_file` read secrets from mounted files (k8s Secret
  volumes) as an alternative to the `*_env` sources.
- Config composition: top-level `include` merges routes/backends/middleware from
  additional files (load-once semantics; cycle- and diamond-safe).
- Host-based routing: `match.hosts` is now enforced (previously parsed but
  ignored). Routes can share a path across different hosts (virtual hosting).
- Header- and query-based route matching: `match.headers` and `match.query`
  require exact values, enabling canary routing and header/query API versioning.
  When routes share a path, the most specific (host/header/query) wins with
  fallback to the catch-all.
- Response cache middleware (`type: cache`): bounded in-memory LRU with per-entry
  TTL, `Cache-Control`/`Vary` awareness, `X-Cache` and `Age` headers, and
  pass-through streaming for oversized bodies.
- OIDC discovery for JWT (`algorithm: rs256`, `oidc_issuer`): resolves `jwks_uri`
  from the issuer's well-known document and defaults `iss` enforcement to the
  discovered issuer.
- OAuth2 token introspection middleware (`type: oauth2`, RFC 7662) for opaque
  tokens, with HTTP Basic client auth, scope enforcement, positive-result caching
  bounded by token expiry, and fail-closed behavior on endpoint errors.
- External authorization middleware (`type: ext_authz`): delegates allow/deny to
  an external HTTP service (Envoy-style), with `forward_headers`, `copy_headers`,
  and configurable `fail_open`.

### Security
- Inbound mTLS: `listener.https.tls.client_ca_file` + `client_auth` require/verify
  client certificates. Configurable `min_version` (1.2 default / 1.3) and a
  hardened TLS 1.2 cipher list.
- Release artifacts ship a CycloneDX SBOM and cosign (keyless) signatures for the
  checksums file and Docker images.
- JWT: validate `iss` and `aud` when configured (`issuer` / `audience`).
- JWKS: require an `https` URL, cap the response body size, and reject RSA keys
  smaller than 2048 bits.
- Gate the admin and metrics endpoints (including the Prometheus endpoint) on the
  real TCP peer instead of the spoofable forwarded client IP.
- Strip Relay-managed identity headers and the `X-Forwarded-*` family from inbound
  requests at the edge; add `listener.strip_request_headers` for app-specific
  identity headers.
- Container runs as a non-root user and ships a `HEALTHCHECK`.

### Added
- Global overload backpressure via `listener.max_concurrent_requests` (fast 503
  when exceeded; internal endpoints exempt).
- Optional admin bearer token (`listener.admin.token_env`) on top of the IP
  allowlist, plus audit logging of admin access and mutations.
- Load testing: an in-process smoke test (`make load`) and a standalone load
  generator (`make loadtest` / `scripts/loadtest`).
- Readiness probe at `/_relay/ready` (503 when no backend has a healthy instance).
- Prometheus metrics: `relay_retry_total`, `relay_circuit_breaker_state`,
  `relay_bulkhead_in_flight`, `relay_bulkhead_rejected_total`,
  `relay_upstream_duration_seconds`.
- `timeouts.websocket_idle` to close idle proxied WebSocket tunnels (now enforced
  on the upstream/backend side of the tunnel as well as the client side).
- `timeouts.read_header` and a default `MaxHeaderBytes` on the listener.
- CI: `-race` test run, `govulncheck` job, and Dependabot configuration.

### Changed
- The in-process metrics summary is sharded per route (no global lock on the
  request hot path); Prometheus remains the primary metrics source.
- JWKS serves a stale key only within a bounded grace window after the TTL, then
  fails closed (a key revoked during an IdP outage stops being honored).
- Health-check goroutines drain deterministically on shutdown/reload and probes
  abort on context cancellation; Fabric telemetry is built only when the queue
  has capacity.
- Responses stream straight to the client; the response is only buffered (up to a
  1 MB cap, then streamed) when a request is retry-eligible.
- Each backend uses a tuned HTTP transport (connection pooling, dial timeouts)
  instead of Go's default transport.
- Circuit breaker: half-open admits a single probe and failures are consecutive
  (a success resets the counter).
- In-memory rate-limit store is sharded; stale buckets are pruned in the
  background. Redis store has a per-call timeout and is closed on reload.
- Access logging is asynchronous and buffered, off the request path.
- Instance selection/release on the hot path is lock-free.
- Graceful shutdown drains HTTP servers before tearing down state.
- Default listener port in `config/example.yaml` is `8088` (matches the
  Dockerfile and docker-compose).
