# Configuration reference

Relay is configured with a single YAML file, selected with `-config <path>` or the
`RELAY_CONFIG` environment variable. Unknown fields are rejected, and the whole
file is validated on load and on every reload (`relay -validate` checks it without
starting the server).

Durations are Go duration strings (`30s`, `1m`, `100ms`). All sections are
optional unless noted; a minimal config needs a listener port, one route, and its
backend.

- [Top-level structure](#top-level-structure)
- [Secret sources (`*_env` / `*_file`)](#secret-sources)
- [`listener`](#listener)
- [`routes`](#routes)
- [`backends`](#backends)
- [`middleware`](#middleware)
- [`observability`](#observability)
- [`reload`, `include`](#reload-and-include)

---

## Top-level structure

```yaml
include: []          # other config files to merge (see below)
listener: {}         # ports, TLS, timeouts, admin, edge hardening
routes: []           # request matching → backend + middleware
backends: []         # upstream pools, load balancing, resilience
middleware: []       # named, reusable middleware referenced by routes
observability: {}    # logs, metrics, tracing
reload: {}           # config hot-reload
```

## Secret sources

Any secret can be supplied without putting the value in the config file. Every
`*_env` field names an environment variable; every `*_file` field names a file to
read (trimmed of surrounding whitespace — ideal for Kubernetes Secret volumes).
When both are set for the same secret, the `*_env` source wins.

| Secret | Env field | File field |
| --- | --- | --- |
| JWT HS256 secret | `secret_env` | `secret_file` |
| OAuth2 client secret | `client_secret_env` | `client_secret_file` |
| Redis URL | `redis_url_env` | `redis_url_file` |
| API keys | `keys_env` | `keys_file` |
| Admin bearer token | `token_env` | `token_file` |

---

## `listener`

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `http.port` | int | — | Plaintext HTTP port. Also accepts cleartext HTTP/2 (h2c). |
| `https.port` | int | — | HTTPS port (enables the TLS server). At least one of `http.port`/`https.port` is required. |
| `https.tls` / `tls` | object | — | TLS settings (see below). `tls` at the listener level is an alias for `https.tls`. |
| `timeouts.read` | duration | — | Full request read timeout. |
| `timeouts.write` | duration | — | Response write timeout. |
| `timeouts.idle` | duration | — | Keep-alive idle timeout. |
| `timeouts.read_header` | duration | `10s` | Header-read timeout (Slowloris mitigation). |
| `timeouts.websocket_idle` | duration | `0` (off) | Idle timeout for proxied WebSocket/upgrade tunnels. |
| `trusted_proxies` | []cidr/ip | `[]` | Peers allowed to set `X-Forwarded-For`. Client IP is taken from `X-Forwarded-For` only when the immediate peer is trusted. |
| `strip_request_headers` | []string | `[]` | Extra inbound headers to drop at the edge (on top of Relay-managed identity + `X-Forwarded-*`). |
| `max_concurrent_requests` | int | `0` (unlimited) | Global in-flight cap; excess requests get a fast `503`. Internal endpoints are exempt. |

### `listener.https.tls`

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `mode` | string | `manual` | `manual` (cert/key files) or `auto` (ACME/Let's Encrypt). |
| `cert_file`, `key_file` | path | — | PEM cert/key for `mode: manual` (hot-rotated on reload). |
| `domains` | []string | — | Domains for `mode: auto`. |
| `acme_cache_dir` | path | — | Required writable, persistent cache for `mode: auto` (mount a volume in containers). |
| `min_version` | string | `1.2` | `1.2` (hardened cipher list) or `1.3`. |
| `client_ca_file` | path | — | Enables inbound mTLS: clients must present a cert signed by this CA. |
| `client_auth` | string | `require` | `require`, `verify_if_given`, or `request` (requires `client_ca_file`). |

### `listener.admin`

Controls the `/_relay/admin/*` management API.

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `allowed_cidrs` | []cidr/ip | loopback | IP ranges (real TCP peer) allowed to call admin endpoints. |
| `token_env` / `token_file` | string | — | Bearer token required in addition to the IP allowlist whenever `allowed_cidrs` extends beyond loopback. |

---

## `routes`

Each route matches requests and forwards them to a backend through an ordered
middleware pipeline. When several routes match, the most specific (host/header/
query-constrained) wins, with fallback to a catch-all.

| Field | Type | Description |
| --- | --- | --- |
| `name` | string | Unique route name (`id` is an alias). |
| `backend` | string | Name of the target backend. |
| `middleware` | []string | Names of middleware to apply, in order (`middlewares` is an alias). |
| `match.path` | string | Exact path match. Mutually exclusive with `path_prefix`. |
| `match.path_prefix` | string | Prefix match (`/v1` matches `/v1` and `/v1/x`, not `/v10`); longest match wins. |
| `match.methods` | []string | Allowed HTTP methods (required). |
| `match.hosts` | []string | Restrict to these `Host` values (port-stripped, case-insensitive). Empty = any host. |
| `match.headers` | map | Require each request header to equal the given value (exact). |
| `match.query` | map | Require each query parameter to equal the given value (exact). |
| `strip_prefix` | string | Strip this leading path prefix before proxying (must start with `/`). |
| `timeout` | duration | Per-route upstream timeout. |
| `max_body_bytes` | int | Reject request bodies larger than this with `413`. `0` = no limit. |
| `rewrite.pattern` / `rewrite.replacement` | string | RE2 regex path rewrite (`$1`, `${name}` capture refs), applied after `strip_prefix`. |
| `add_request_headers` | map | Inject headers into the outbound request. Value `${req.Header-Name}` copies an inbound header. **Note:** `${req.*}` values are untrusted client input — do not use them to set headers a backend trusts for authorization. |

---

## `backends`

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | string | — | Unique backend name. |
| `protocol` | string | `http1` | `http1` (HTTP/1.1, h2 via ALPN for https) or `h2c` (cleartext HTTP/2, e.g. gRPC). `h2c` cannot be combined with `tls`. |
| `strategy` | string | — | `round_robin`, `least_connections`, or `weighted_random`. |
| `instances[].url` | url | — | Upstream URL (`http`/`https`). |
| `instances[].weight` | int | `1` | Traffic share for `weighted_random` (0 → 1). |
| `health_check.path` | path | — | Active health-check path (enables checks when set with `interval`). |
| `health_check.interval` | duration | — | Time between checks. |
| `health_check.timeout` | duration | — | Per-check timeout. |
| `circuit_breaker.threshold` | int | `0` (off) | Consecutive failures that trip the circuit. |
| `circuit_breaker.timeout` | duration | `30s` | How long the circuit stays open before a probe. |
| `bulkhead.max_concurrent` | int | `0` (off) | Max simultaneous in-flight requests to this backend; excess gets a fast `503`. |
| `tls.ca_file` | path | — | CA bundle to verify the backend cert (system roots when empty). |
| `tls.cert_file`, `tls.key_file` | path | — | Client cert/key for outbound mTLS. |
| `tls.insecure_skip_verify` | bool | `false` | Disable backend cert verification (dev only). |

### `backends[].retry`

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `attempts` | int | `1` (off) | Max total attempts including the first. |
| `on` | []string | — | Retry conditions: `5xx` and/or `network_error`. |
| `backoff_init` | duration | `100ms` | Initial backoff. |
| `backoff_max` | duration | `1s` | Backoff cap. |
| `allow_unsafe` | bool | `false` | Permit retrying non-safe methods (POST/PUT/PATCH/DELETE). |
| `budget_ratio` | float | `0` (unlimited) | Cap retries as a fraction of traffic (token bucket) to prevent retry storms. |
| `budget_tokens` | int | `100` | Token-bucket capacity / initial burst when `budget_ratio > 0`. |

---

## `middleware`

Each entry is a named, reusable middleware referenced by routes:

```yaml
middleware:
  - name: my-jwt
    type: jwt
    config: { ... }
```

Common fields: `name` (unique), `type` (one of the types below), `config`
(type-specific). Supported `type` values: `jwt`, `rate_limit`, `body_limit`,
`ip_filter`, `cors`, `header`, `api_key`, `cache`, `oauth2`, `ext_authz`.

### `jwt`

| `config` field | Default | Description |
| --- | --- | --- |
| `algorithm` | `hs256` | `hs256` or `rs256`. |
| `secret_env` / `secret_file` | — | HS256 shared secret (≥ 32 bytes). |
| `public_key_file` | — | RS256 static PEM public key. |
| `jwks_url` | — | RS256 JWKS endpoint (`https` required). |
| `oidc_issuer` | — | RS256 via OIDC discovery (`https`); resolves `jwks_uri` and defaults `issuer`. |
| `jwks_cache_ttl` | `5m` | JWKS cache TTL. |
| `header` | `Authorization` | Header carrying the token (`Bearer` scheme for `Authorization`). |
| `issuer` / `audience` | — | Enforce the `iss` / `aud` claims when set. |
| `claims_to_headers` | — | Map of claim → outbound header to inject. |
| `jwt_log_failures` | `false` | Log structured warnings on rejection (never the raw token). |

`public_key_file`, `jwks_url` and `oidc_issuer` are mutually exclusive.

### `rate_limit`

| `config` field | Default | Description |
| --- | --- | --- |
| `strategy` | — | `sliding_window` (only supported strategy). |
| `limit` | — | Max requests per window (> 0). |
| `window` | — | Window duration (> 0). |
| `by` | — | Key: `ip`, `route`, or `api_key`. |
| `store` | `memory` | `memory` (per-instance, sharded) or `redis` (distributed). |
| `redis_url` / `redis_url_env` / `redis_url_file` | — | Redis connection URL (`redis://`, `rediss://`) when `store: redis`. |
| `fail_open` | `false` | When `store: redis`, allow requests if Redis is unavailable. Keep `false` for protected routes. |

### `body_limit`

| `config` field | Description |
| --- | --- |
| `max_bytes` | Reject bodies larger than this with `413` (> 0). |

### `ip_filter`

| `config` field | Description |
| --- | --- |
| `allow` / `deny` | Lists of IPs/CIDRs. Allow is applied first; deny can override. At least one required. |

### `cors`

| `config` field | Description |
| --- | --- |
| `allowed_origins` | Allowed origins (required). |
| `allowed_methods` | Allowed methods (required). |
| `allowed_headers` | Allowed request headers. |
| `allow_credentials` | Send `Access-Control-Allow-Credentials`. |

### `header`

| `config` field | Description |
| --- | --- |
| `request_set` / `request_del` | Set / delete request headers before proxying. |
| `response_set` / `response_del` | Set / delete response headers. |

At least one of the four is required.

### `api_key`

| `config` field | Description |
| --- | --- |
| `key_header` / `key_query` | Where to read the key from. |
| `keys_env` / `keys_file` | Source of valid keys (one required). |
| `key_to_header` | Map the matched key to an outbound header. |

### `cache`

| `config` field | Default | Description |
| --- | --- | --- |
| `ttl` | `60s` | Default cache lifetime when the upstream sets no `max-age`. |
| `methods` | `[GET, HEAD]` | Cacheable request methods. |
| `cacheable_status` | `[200]` | Cacheable response status codes. |
| `max_object_bytes` | `1048576` | Max cacheable body; larger responses stream uncached. |
| `max_entries` | `1000` | LRU capacity. |
| `vary` | `[]` | Request headers folded into the cache key. |

Honors request/response `Cache-Control` (`no-store`, `no-cache`, `private`,
`max-age`/`s-maxage`), skips `Set-Cookie` responses, honors the origin's `Vary`,
and adds `X-Cache` / `Age`.

**Authenticated requests are safe by default.** A request carrying `Authorization`
or `Cookie` is only cached when the origin explicitly marks the response shareable
(`Cache-Control: public` or `s-maxage`); otherwise it is never stored, and a
non-`public` cached entry is never served to an authenticated request. This
prevents one user's response from being returned to another (RFC 7234 §3.2). To
cache per-user responses intentionally, fold the identity into the key with
`vary: [Authorization]`.

### `oauth2` (RFC 7662 token introspection)

| `config` field | Default | Description |
| --- | --- | --- |
| `introspection_url` | — | Introspection endpoint (`https` required). |
| `client_id` | — | Client ID for HTTP Basic auth. |
| `client_secret_env` / `client_secret_file` | — | Client secret. |
| `required_scopes` | — | Require every listed scope (else `403`). |
| `cache_ttl` | `60s` | Positive-result cache, bounded by the token's own expiry. |
| `header` | `Authorization` | Header carrying the opaque token. |

Fails closed (`503`) when the endpoint is unreachable.

### `ext_authz` (external authorization)

| `config` field | Default | Description |
| --- | --- | --- |
| `authz_url` | — | External authorizer (`http`/`https`). |
| `forward_headers` | — | Inbound headers to include on the probe (method/URI/host/client-IP are always sent). |
| `copy_headers` | — | Headers from a 2xx response to inject into the upstream request. |
| `authz_timeout` | `2s` | Per-call timeout. |
| `fail_open` | `false` | On error/unreachable: allow (`true`) or deny with `503` (`false`). |

`2xx` allows; `401`/`403` deny; other statuses follow `fail_open`.

---

## `observability`

### `logs`

| Field | Default | Description |
| --- | --- | --- |
| `level` | `info` | Log level. |
| `format` | `json` | `json` or text. |
| `file` | — | Access-log file; empty logs to stdout. |
| `max_size_mb` | — | Size-based rotation threshold. |
| `max_age_days`, `compress` | — | Rotation retention / compression. |

### `metrics` / `prometheus`

| Field | Default | Description |
| --- | --- | --- |
| `prometheus.path` | `/_relay/metrics/prometheus` | Prometheus scrape path. |
| `prometheus.allowed_cidrs` | loopback | Extra source ranges (real TCP peer) allowed to scrape metrics. |

### `tracing`

| Field | Default | Description |
| --- | --- | --- |
| `enabled` | `false` | Enable OpenTelemetry tracing. |
| `exporter` | — | `otlp_grpc`, `otlp_http`, or `stdout`. |
| `endpoint` | SDK default | Collector address. |
| `sample_rate` | `1.0` | Fraction of traces sampled (0.0–1.0). |
| `service_name` | `relay` | Service name reported to the collector. |

### `fabric` / `dashboard`

| Field | Description |
| --- | --- |
| `fabric.enabled`, `fabric.service_name`, `fabric.queue_size` | Algoryn Fabric protobuf telemetry. |

---

## reload and include

### `reload`

| Field | Description |
| --- | --- |
| `watch` | Watch the config file and hot-reload on change (`enabled` is an alias). |
| `debounce` | Debounce window (required when `watch` is on). |

### `include`

A top-level list of other config files whose `routes`, `backends` and
`middleware` are merged into this config. Paths are relative to the including
file (or absolute). Files are loaded once, so shared bases and cycles are handled
safely; duplicate names across files are rejected by validation.

```yaml
include:
  - backends/payments.yaml
  - routes/public.yaml
```
