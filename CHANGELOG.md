# Changelog

All notable changes to Relay are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project aims to follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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
