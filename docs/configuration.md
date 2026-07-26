# Configuration reference

Relay is configured with a single YAML file, selected with `-config <path>` or the
`RELAY_CONFIG` environment variable. Unknown fields are rejected, and the whole
file is validated on load and on every reload (`relay -validate` checks it without
starting the server).

Durations are Go duration strings (`30s`, `1m`, `100ms`). All sections are
optional unless noted; a minimal config needs a listener port, one route, and its
backend.

- [Top-level structure](#top-level-structure)
- [Compatibility and migrations](#compatibility-and-migrations)
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
observability: {}    # logs, Prometheus, tracing, Fabric telemetry
reload: {}           # config hot-reload
```

## Compatibility and migrations

Relay is pre-1.0. Configuration compatibility is not guaranteed across minor
versions when removing fields that have no runtime effect. Such removals are
treated as breaking changes: they are called out in the changelog, examples are
updated in the same release, and the strict YAML decoder rejects stale fields
instead of silently ignoring them. Run `relay -config relay.yaml -validate`
before upgrading.

The legacy `observability.dashboard`, top-level `storage`, and
`observability.metrics.flush_interval` settings have been removed because Relay
never served the React dashboard, persisted data, or buffered metric flushes.
Delete those blocks when migrating. Prometheus metrics remain available under
`observability.prometheus`, and the shipped Grafana dashboard and Prometheus
rules remain supported deployment artifacts.

## Secret sources

Any secret can be supplied without putting the value in the config file. Every
`*_env` field names an environment variable; every `*_file` field names a file to
read (trimmed of surrounding whitespace — ideal for Kubernetes Secret volumes).
When both are set for the same secret, the `*_env` source wins.

| Secret | Env field | File field |
| --- | --- | --- |
| JWT HS256 secret | `secret_env` | `secret_file` |
| OAuth2 client secret | `client_secret_env` | `client_secret_file` |
| Redis URL (rate limit, response cache, or ACME cache) | `redis_url_env` | `redis_url_file` |
| API keys | `keys_env` | `keys_file` |
| Admin bearer token | `token_env` | `token_file` |
| Health endpoint bearer token | `token_env` | `token_file` |

---

## `listener`

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `http.port` | int | — | Plaintext HTTP port. Also accepts cleartext HTTP/2 (h2c). |
| `http.canonical_host` | string | — | Fixed hostname/IP for HTTP→HTTPS redirects. Must not include a scheme, path, or port. |
| `http.redirect_allowed_hosts` | []string | `[]` | Valid request hosts that may be preserved in HTTP→HTTPS redirects. Required when redirecting without `canonical_host`; an unlisted/malformed Host gets `400` and no redirect. |
| `https.port` | int | — | HTTPS port (enables the TLS server). At least one of `http.port`/`https.port` is required. |
| `https.tls` / `tls` | object | — | TLS settings (see below). `tls` at the listener level is an alias for `https.tls`. |
| `timeouts.read` | duration | — | Full request read timeout. |
| `timeouts.write` | duration | — | Response write timeout. |
| `timeouts.idle` | duration | — | Keep-alive idle timeout. |
| `timeouts.read_header` | duration | `10s` | Header-read timeout (Slowloris mitigation). |
| `timeouts.websocket_idle` | duration | `0` (off) | Idle timeout for proxied WebSocket/upgrade tunnels. |
| `trusted_proxies` | []cidr/ip | `[]` | Peers allowed to extend `X-Forwarded-For`. Relay normalizes valid IP hops and appends the immediate peer; an untrusted peer's entire inbound chain is discarded. Client IP is resolved right-to-left across trusted hops. Public CIDRs are rejected. |
| `emit_forwarded_header` | bool | `false` | Generate RFC 7239 `Forwarded` from Relay-owned, sanitized values. Inbound `Forwarded` is always discarded. |
| `strip_request_headers` | []string | `[]` | Extra inbound headers to drop at the edge (on top of Relay-managed identity + `X-Forwarded-*`). |
| `max_concurrent_requests` | int | `0` (unlimited) | Global in-flight cap; excess requests get a fast `503`. Internal endpoints are exempt. |
| `max_connections_per_ip` | int | `0` (disabled) | Simultaneous TCP connection cap per real peer IP. Excess connections are closed before HTTP parsing. |
| `max_request_body_bytes` | int64 | `10485760` | Global proxied-request body cap (10 MiB). A route's `max_body_bytes` overrides it. |

`max_connections_per_ip` runs at the TCP listener, before request headers exist.
It therefore always keys on the immediate peer from `RemoteAddr` and never on
`X-Forwarded-For`, even when that peer is in `trusted_proxies`. Behind a load
balancer, all connections may appear under the load balancer's IP; prefer
`max_concurrent_requests`, backend bulkheads, or request rate limits there
instead of treating a forwarded address as the TCP peer. The setting is
process-local and hot-reloadable; lowering it does not terminate established
connections, but rejects new ones until occupancy falls below the new limit.

When both HTTP and HTTPS listeners are enabled, configure `canonical_host`,
`redirect_allowed_hosts`, or both. `canonical_host` always supplies the redirect
authority; when an allowlist is also present, the incoming Host must be listed.
Without a canonical host, Relay preserves only an allowlisted Host. The HTTPS
port is taken from `https.port` (omitted for 443), including bracket-safe IPv6.

### `listener.https.tls`

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `mode` | string | `manual` | `manual` (cert/key files) or `auto` (ACME/Let's Encrypt). |
| `cert_file`, `key_file` | path | — | Default PEM cert/key for `mode: manual`; used for clients without SNI and for SNI names covered by its SAN (hot-reloaded). |
| `certificates` | []object | `[]` | Additional manual-mode SNI certificates. Each entry has `hosts`, `cert_file`, and `key_file`. |
| `domains` | []string | — | Domains for `mode: auto`; included in the Redis cache namespace. |
| `acme_email` | string | — | ACME account email; included in the Redis cache namespace. |
| `acme_cache` | object | — | ACME cache backend. Use `filesystem` for one replica or `redis` for shared cache and issuance coordination. |
| `acme_cache_dir` | path | — | Legacy shorthand for `acme_cache: {backend: filesystem, directory: ...}`. |
| `replicas` | int | `1` | Declared replicas sharing this TLS config. Values above 1 require Redis coordination. |
| `distributed` | bool | `false` | Required acknowledgement when `acme_cache.backend: redis`; multi-replica filesystem configs are rejected. |
| `min_version` | string | `1.2` | `1.2` (hardened cipher list) or `1.3`. |
| `cipher_suites` | []string | hardened TLS 1.2 set | Optional IANA names from Relay's supported AEAD/PFS TLS 1.2 suites. Not valid with `min_version: "1.3"`. |
| `client_ca_file` | path | — | Enables inbound mTLS: clients must present a cert signed by this CA. |
| `client_auth` | string | `require` | `require`, `verify_if_given`, or `request` (requires `client_ca_file`). |

Manual SNI entries accept exact DNS names and one-label wildcards such as
`*.tenant.example.com`. Wildcards must be the complete left-most label and
cannot target a public suffix. Duplicate names are rejected case-insensitively.
Every configured name must be covered by the leaf certificate SAN; malformed
or mismatched cert/key pairs fail startup or reload. Exact matches win over
wildcards, and a wildcard matches exactly one label. For an unknown SNI, Relay
uses the default certificate only when that certificate's SAN covers the name;
otherwise the handshake fails without exposing another host's certificate.

```yaml
listener:
  https:
    port: 8443
    tls:
      mode: manual
      cert_file: /etc/relay/tls/default.crt
      key_file: /etc/relay/tls/default.key
      certificates:
        - hosts: [api.example.com]
          cert_file: /etc/relay/tls/api.crt
          key_file: /etc/relay/tls/api.key
        - hosts: ["*.tenant.example.com"]
          cert_file: /etc/relay/tls/tenants.crt
          key_file: /etc/relay/tls/tenants.key
      min_version: "1.2"
      cipher_suites:
        - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
```

Hot reload prepares certificates, SNI routing, client CA/client authentication,
minimum version, and cipher suites as one TLS configuration. New handshakes see
the new configuration only after every file and parameter validates; on failure
the previous TLS and request-routing state remains active. Listener HTTP/HTTPS
ports and switching between `manual` and `auto` are restart-only changes and a
reload that attempts either is rejected explicitly.

For one replica, the filesystem backend remains supported:

```yaml
mode: auto
domains: [api.example.com]
acme_email: ops@example.com
replicas: 1
acme_cache:
  backend: filesystem
  directory: /var/lib/relay/acme
```

For multiple replicas, use Redis. Relay stores `autocert.Cache` data in a
namespace derived from the normalized domain set and ACME account, and uses a
renewable owner-token lease to ensure only one replica issues a missing
certificate. Redis errors fail closed: Relay does not fall back to independent
issuance.

```yaml
mode: auto
domains: [api.example.com]
acme_email: ops@example.com
replicas: 3
distributed: true
acme_cache:
  backend: redis
  redis_url_env: RELAY_ACME_REDIS_URL
  # Or redis_url_file: /run/secrets/acme-redis-url
  namespace: production
  operation_timeout: 500ms
  lock_wait_timeout: 3m
  lock_ttl: 2m
  lock_renew_interval: 30s
```

`operation_timeout` defaults to `500ms`, `lock_wait_timeout` to `3m`, and
`lock_ttl` to `2m`; renewal defaults to one third of the TTL and must remain
below it. Lease release and publication are token-checked atomically in Redis,
so an expired owner cannot delete another replica's lease or publish stale
certificate data.

### `listener.health`

`/_relay/health` is a liveness signal with a constant minimal response:
`200 {"status":"ok"}`. It never inspects or identifies backends.
`/_relay/ready` returns only `{"status":"ready"}` (200) or
`{"status":"not_ready"}` (503); backend names, URLs, counts, and failure reasons
are never included. Both endpoints are public by default so Kubernetes HTTP
probes remain compatible.

```yaml
listener:
  health:
    access:
      # Optional: when present, the immediate TCP peer must match. X-Forwarded-For
      # is never trusted for this gate.
      allowed_cidrs: [10.42.0.0/16]
      # Optional additional bearer token; env wins over file.
      token_env: RELAY_HEALTH_TOKEN
      # token_file: /run/secrets/relay-health-token
    readiness:
      # any (default), all, or critical
      mode: critical
      critical_backends: [orders-backend, payments-backend]
```

`any` is ready when at least one configured backend can serve (and also when no
backends exist). `all` requires every backend. `critical` requires every named
critical backend; the list must be non-empty, unique, and contain only configured
backend names. `critical_backends` is rejected with other modes.

For diagnostics, use `GET /_relay/admin/readiness` (or the shorter
`/_relay/admin/ready`). It returns the evaluated policy, backend and instance
names/URLs, health/ejection state, and bounded reasons, and is protected by the
same real-peer CIDR plus constant-time bearer-token checks as every admin
endpoint. Do not expose the admin API publicly.

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
| `propagate_client_identity` | object | Optional route override for the backend mTLS client-identity propagation policy below. |

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
| `health_check.method` | string | `GET` | Safe probe method: `GET`, `HEAD`, or `OPTIONS`. |
| `health_check.expected_status` | int/string/list/object | any `2xx` | Exact (`204`), inclusive range (`"200-399"`), list (`[200, 204]`), or explicit `exact`/`range`/`list` object. |
| `health_check.headers` | map | — | Fixed request headers. Control characters and hop-by-hop headers are rejected. |
| `health_check.body` | object | — | Optional bounded matcher: exactly one of `exact`, `contains`, or RE2 `regex`. |
| `health_check.max_body_bytes` | int | `65536` | Maximum response bytes read by a body matcher; hard cap 1 MiB. |
| `outlier_detection.window` | duration | `30s` | Rolling passive-failure window per instance. |
| `outlier_detection.consecutive_failures` | int | `0` | Consecutive network/5xx/failed-active-check outcomes before ejection. |
| `outlier_detection.failure_rate_percent` | float | `0` | Failure-rate threshold; requires `minimum_volume`. |
| `outlier_detection.minimum_volume` | int | `0` | Minimum outcomes in the rolling window before rate ejection. |
| `outlier_detection.base_ejection_duration` | duration | `30s` | Initial ejection duration. |
| `outlier_detection.max_ejection_duration` | duration | `5m` | Cap for exponential ejection duration. |
| `outlier_detection.max_ejection_percent` | int | `100` | Maximum percentage of instances ejected concurrently. |
| `outlier_detection.success_recovery` | bool | `false` | Let a successful active probe recover an instance before duration expiry. |
| `circuit_breaker.threshold` | int | `0` (off) | Consecutive failures that trip the circuit. |
| `circuit_breaker.timeout` | duration | `30s` | How long the circuit stays open before a probe. |
| `bulkhead.max_concurrent` | int | `0` (off) | Max simultaneous in-flight requests to this backend; excess gets a fast `503`. |
| `tls.ca_file` | path | — | CA bundle to verify the backend cert (system roots when empty). |
| `tls.cert_file`, `tls.key_file` | path | — | Client cert/key for outbound mTLS. |
| `tls.insecure_skip_verify` | bool | `false` | Disable backend cert verification (dev only). Requires explicit acknowledgement. |
| `tls.acknowledge_insecure_skip_verify` | bool | `false` | Must be `true` when certificate verification is disabled. |
| `propagate_client_identity.enabled` | bool | `false` | Propagate selected attributes of a verified inbound mTLS client certificate through Relay-owned headers. |
| `propagate_client_identity.fields` | []string | `[]` | Explicit allowlist: `subject`, `san_dns`, `san_email`, `san_ip`, `san_uri`, `fingerprint_sha256`. Raw/PEM certificates are never forwarded. |
| `propagate_client_identity.acknowledge_verified_https` | bool | `false` | Required acknowledgement when the upstream uses verified HTTPS without outbound mTLS. |

Identity propagation fails validation unless every backend instance uses HTTPS
with certificate verification enabled. Outbound mTLS satisfies the stronger
trust-boundary requirement; otherwise
`acknowledge_verified_https: true` is mandatory. A route may replace its
backend's policy with its own `propagate_client_identity` object. Relay always
strips the reserved `X-Relay-Client-Cert-*` headers before setting allowlisted
values from `TLS.VerifiedChains`; an absent or unverified client certificate
produces no identity headers. Subject/SAN values containing controls or exceeding
the bounded header value size are omitted.

```yaml
propagate_client_identity:
  enabled: true
  fields: [san_uri, fingerprint_sha256]
  acknowledge_verified_https: true
```

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

Active checks use the backend's normal transport, including custom CA roots and
client certificates. Passive detection observes every proxy/retry attempt and
active-check result; client cancellation is not counted as an upstream failure.
Ejection and recovery expose bounded-reason Prometheus metrics and appear in
backend admin snapshots.

```yaml
health_check:
  path: /ready
  method: GET
  interval: 10s
  timeout: 2s
  expected_status:
    list: [200, 204]
  headers:
    X-Relay-Probe: readiness
  body:
    regex: '^ready'
  max_body_bytes: 4096
outlier_detection:
  window: 30s
  consecutive_failures: 5
  failure_rate_percent: 50
  minimum_volume: 20
  base_ejection_duration: 30s
  max_ejection_duration: 5m
  max_ejection_percent: 50
  success_recovery: true
```

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
`ip_filter`, `cors`, `header`, `security_headers`, `api_key`, `cache`, `oauth2`,
`ext_authz`.

### `jwt`

| `config` field | Default | Description |
| --- | --- | --- |
| `algorithm` | `hs256` | `hs256` or `rs256`. |
| `secret_env` / `secret_file` | — | HS256 shared secret (≥ 32 bytes). |
| `public_key_file` | — | RS256 static PEM public key. |
| `jwks_url` | — | RS256 JWKS endpoint (`https` required); also requires non-empty `issuer` and `audience`. |
| `oidc_issuer` | — | RS256 via OIDC discovery (`https`); resolves `jwks_uri` and requires non-empty `issuer` and `audience`. |
| `jwks_cache_ttl` | `5m` | How long a successful JWKS set is used before Relay refreshes it. |
| `jwks_stale_grace` | `0s` | Opt-in window for keys removed by a successful refresh or left stale by a failed refresh (`0s`–`24h`). |
| `header` | `Authorization` | Header carrying the token (`Bearer` scheme for `Authorization`). |
| `issuer` / `audience` | — | Enforce the `iss` / `aud` claims. Both are mandatory with remote JWKS or OIDC discovery, but remain optional for HS256 and static PEM keys. |
| `claims_to_headers` | — | Map of claim → outbound header to inject. |
| `jwt_log_failures` | `false` | Log structured warnings on rejection (never the raw token). |

`public_key_file`, `jwks_url` and `oidc_issuer` are mutually exclusive.

`jwks_cache_ttl` controls refresh frequency; it is not a revocation grace
period. With the secure default `jwks_stale_grace: 0s`, a key absent from a
successfully refreshed JWKS is rejected immediately, and an expired cache fails
closed if refresh fails. A positive grace trades revocation speed for
availability: removed keys remain usable only until their removal time plus the
grace, while refresh failures can use the last successful set only until
`last successful refresh + jwks_cache_ttl + jwks_stale_grace`. Failed requests
never move either deadline. Keep the grace as short as the issuer's rotation and
outage requirements permit; validation caps it at 24 hours.

Pre-1.0 migration: configurations using `jwks_url` or `oidc_issuer` must now
declare both `issuer` and `audience`. Header-only API keys and fail-closed
external authorization keep their previous behavior. Existing `key_query` and
`ext_authz` `fail_open: true` configurations fail validation with the exact
acknowledgement field that must be reviewed and added.

### `rate_limit`

| `config` field | Default | Description |
| --- | --- | --- |
| `strategy` | — | `sliding_window` (only supported strategy). |
| `limit` | — | Max requests per window (> 0). |
| `window` | — | Window duration (> 0). |
| `by` | — | Legacy key: `ip`, `route`, or `api_key`. Mutually exclusive with `key.selectors`. |
| `key.selectors` | — | Ordered selectors: `ip`, `route`, `header` (requires `name`), `claim`/`jwt_claim` (requires `claim` or `name`), `tenant`, or `identity`. Simple selectors may be scalar strings. |
| `key.fallback` | — | Single selector used as the whole key when any primary selector is missing. |
| `key.reject_missing` | `false` | Return `400 rate_limit_key_missing` instead of using the shared missing bucket. |
| `key.namespace` | `relay:ratelimit:v1` | Stable operator namespace (maximum 64 safe characters). |
| `store` | `memory` | `memory` (per-instance, sharded) or `redis` (distributed). |
| `memory_max_buckets` | `100000` | Strict per-process bucket cap for the memory store; LRU eviction occurs within shards at capacity. |
| `memory_bucket_ttl` | `window` | Idle bucket TTL for the memory store; must be at least `window`. |
| `memory_cleanup_interval` | `1m` | Interval for the single background stale-bucket cleanup loop. |
| `redis_url` / `redis_url_env` / `redis_url_file` | — | Redis connection URL (`redis://`, `rediss://`) when `store: redis`. |
| `fail_open` | `false` | When `store: redis`, allow requests if Redis is unavailable. Keep `false` for protected routes. |

The memory store preserves exact sliding-window request timestamps, uses no
per-bucket goroutines, and exports `relay_rate_limit_memory_buckets` plus
`relay_rate_limit_memory_evictions_total`.

Selectors are composed in declaration order. Relay length-prefixes every
descriptor and value, then stores only a SHA-256 digest under the namespace.
This prevents component-boundary collisions, keeps Redis keys bounded, and
avoids putting IPs, identities, claims, or header values in bucket names.
Memory and Redis receive the exact same derived key.

`identity`, `tenant`, and `claim`/`jwt_claim` read only Relay-owned request
context produced by a successful `jwt`, `api_key`, `oauth2`, or `ext_authz`
middleware; inbound headers cannot populate it. A route using one of these
selectors (including as `fallback`) must list the authentication middleware
before the rate limiter. `claim` accepts scalar claims published into that
context (verified JWT scalars, OAuth2 introspection fields, or
`X-Relay-Auth-Claim-*` from ext_authz). `identity` uses the verified subject, or
the non-secret key ID when no subject exists.

```yaml
- name: account-write-limit
  type: rate_limit
  config:
    strategy: sliding_window
    limit: 100
    window: 1m
    key:
      namespace: orders-write:v1
      selectors:
        - {type: tenant}
        - {type: claim, claim: account_id}
        - {type: route}
      fallback: {type: ip}
      reject_missing: true
```

On the route, place (for example) `jwt-auth` before `account-write-limit`.
JWT publishes `sub`, scalar verified claims, `tenant`/`tenant_id`, and `kid`.
OAuth2 introspection publishes `sub`, `tenant`/`tenant_id`, and
`client_id` (or `jti`) without retaining the bearer token. API-key auth
publishes the configured caller ID; secret-only entries use a SHA-256 key ID in
context rather than the secret.

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

### `security_headers`

Reusable response hardening with `preset: secure` or `preset: strict`. Each
preset supplies HSTS, CSP, `X-Content-Type-Options`, `Referrer-Policy`, and
`Permissions-Policy`; `secure` uses `X-Frame-Options: DENY`, while `strict` uses
CSP `frame-ancestors 'none'`. Override any field below, or set it to `off`:

| `config` field | Description |
| --- | --- |
| `preset` | `secure` or `strict`; optional when at least one explicit header is set. |
| `strict_transport_security` | HSTS value. `preload` requires `includeSubDomains` and at least one year of `max-age`. |
| `content_security_policy` | CSP value. Unsafe script execution and insecure frame ancestors are rejected. |
| `x_frame_options` | `DENY`, `SAMEORIGIN`, or `off`. Cannot coexist with CSP `frame-ancestors`. |
| `x_content_type_options` | `nosniff` or `off`. |
| `referrer_policy` | Referrer policy; `unsafe-url` is rejected. |
| `permissions_policy` | Permissions Policy; wildcard grants are rejected. |

```yaml
- name: browser-security
  type: security_headers
  config:
    preset: secure
    x_frame_options: off
    content_security_policy: "default-src 'self'; frame-ancestors 'self'"
    referrer_policy: strict-origin-when-cross-origin
```

### `api_key`

| `config` field | Description |
| --- | --- |
| `key_header` | Header carrying the key (`X-API-Key` by default). |
| `key_query` | Query parameter carrying the key. Disabled when empty; setting it requires `acknowledge_api_key_in_query: true`. |
| `acknowledge_api_key_in_query` | Explicitly acknowledge that query-string credentials can leak through access logs, intermediary/browser caches, and `Referer` headers. Validation-only; it does not change request handling. |
| `keys_env` / `keys_file` | Source of valid keys (one required). |
| `key_to_header` | Map the matched key to an outbound header. |

Prefer `key_header`. If compatibility with a legacy client forces query-string
keys, use a narrowly scoped configuration and explicitly acknowledge the risk:

```yaml
- name: legacy-query-api-key
  type: api_key
  config:
    key_query: api_key
    acknowledge_api_key_in_query: true
    keys_env: RELAY_API_KEYS
```

### `cache`

| `config` field | Default | Description |
| --- | --- | --- |
| `ttl` | `60s` | Default cache lifetime when the upstream sets no `max-age`. |
| `methods` | `[GET, HEAD]` | Cacheable request methods. |
| `cacheable_status` | `[200]` | Cacheable response status codes. |
| `max_object_bytes` | `1048576` | Max cacheable body; larger responses stream uncached. |
| `max_entries` | `1000` | LRU capacity for `store: memory`. Ignored by Redis (TTL governs retention). |
| `vary` | `[]` | Request headers folded into the cache key. |
| `store` | `memory` | `memory` (per-instance LRU) or `redis` (shared across replicas). |
| `redis_url` / `redis_url_env` / `redis_url_file` | — | Redis connection URL (`redis://`, `rediss://`) when `store: redis`. |
| `namespace` | `relay:cache:v1` | Redis key prefix (maximum 64 safe characters). |
| `operation_timeout` | `100ms` | Bound for a single Redis cache command. |
| `fail_open` | `false` | When `store: redis`, treat lookup/invalidation errors as a miss/bypass (`true`) or return `503` (`false`). Write failures never fail the origin response. Prefer `fail_open: true` when the cache is an optimization. |

Honors request/response `Cache-Control` (`no-store`, `no-cache`, `private`,
`max-age`/`s-maxage`), skips `Set-Cookie` responses, honors the origin's `Vary`,
and adds `X-Cache` / `Age`. Redis keys are SHA-256 digests under `namespace`, so
logical keys stay bounded and do not embed raw header values.

`PURGE` invalidates the cached `GET`/`HEAD` variants for the request URL (including
configured `vary` headers) and returns `200` with `X-Cache: PURGED` without
forwarding to the origin.

**Authenticated requests are safe by default.** A request carrying `Authorization`
or `Cookie` is only cached when the origin explicitly marks the response shareable
(`Cache-Control: public` or `s-maxage`); otherwise it is never stored, and a
non-`public` cached entry is never served to an authenticated request. This
prevents one user's response from being returned to another (RFC 7234 §3.2). To
cache per-user responses intentionally, fold the identity into the key with
`vary: [Authorization]`.

```yaml
- name: page-cache
  type: cache
  config:
    store: redis
    redis_url_env: RELAY_REDIS_URL
    namespace: pages:v1
    ttl: 30s
    max_object_bytes: 1048576
    vary: [Accept-Encoding]
    fail_open: true
```

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
| `authz_url` | — | External authorizer (`https` required by default). |
| `allow_insecure_http` | `false` | Explicitly permit plaintext HTTP only for a trusted internal network. |
| `authz_method` | `GET` | Authorization call method: `GET`, `POST`, or `HEAD`. Body modes require `POST`. |
| `authz_body` | `none` | Probe body: `none`, bounded/replayable `original`, or structured `metadata`. |
| `authz_max_body_bytes` | `1048576` | Maximum authorization body; bounds buffered `original` data and serialized metadata. |
| `authz_content_type` | mode-dependent | Valid media type override. Metadata requires `application/json` or a `+json` type; original otherwise inherits the inbound type. |
| `forward_headers` | — | Explicit allowlist of inbound headers sent on the probe and included in metadata. Method/URI/host/client-IP are always sent separately. |
| `copy_headers` | — | Headers from a 2xx response to inject into the upstream request. |
| `authz_timeout` | `2s` | Per-call timeout. |
| `fail_open` | `false` | On error/unreachable: allow (`true`) or deny with `503` (`false`). |
| `acknowledge_ext_authz_fail_open` | `false` | Required when `fail_open: true`; explicitly acknowledges that authorizer failures will bypass authorization. Validation-only. |

`2xx` allows; `401`/`403` deny; other statuses follow `fail_open`.
The default `GET`/`none` contract is backward compatible. `original` never reads
streaming, chunked, or protocol-upgrade/WebSocket bodies. An oversized body
returns `413` even with `fail_open`; a body that cannot safely be inspected
returns `503`, or bypasses authorization only when explicitly configured
fail-open and the untouched body can still be forwarded. Cancellation never
fails open. Metadata contains method, request URI, host, resolved client IP,
request ID, verified mTLS identity when available, and only `forward_headers`;
credentials are not included unless explicitly allowlisted.
On a successful decision, the authorizer may also return
`X-Relay-Auth-Subject`, `X-Relay-Auth-Tenant`, `X-Relay-Auth-Key-Id`, and
`X-Relay-Auth-Claim-<name>`. Relay copies these values into its private identity
context for downstream selectors. Client headers with these names are ignored;
the values are read only from the authorizer response. They are not forwarded
upstream unless separately listed in `copy_headers`.

```yaml
- name: metadata-authz
  type: ext_authz
  config:
    authz_url: https://authz.internal.example/check
    authz_method: POST
    authz_body: metadata
    authz_content_type: application/json
    forward_headers: [X-Tenant-ID]
```

---

## `observability`

### `logs`

| Field | Default | Description |
| --- | --- | --- |
| `level` | `info` | Log level. |
| `format` | `json` | `json` or `text`, for both stdout and file sinks. |
| `file` | — | Access-log file; empty logs to stdout. |
| `max_size_mb` | — | Size-based rotation threshold. |
| `max_age_days`, `compress` | — | Rotation retention / compression. |

Access-log attributes are selected from the fixed allowlist `method`, `path`,
`route`, `backend`, `status`, `duration`, `bytes`, `client_ip`, `request_id`,
`trace_id`, `span_id`, `host`, and `user_agent`. An empty `access.fields` keeps
the backward-compatible default (`method`, `path`, `status`, `duration`,
`route`, `backend`, `client_ip`, `request_id`). `duration` is emitted as
`duration_ms`. Request headers and query parameters are never collected unless
explicitly selected.

```yaml
observability:
  logs:
    level: info
    format: json
    access:
      fields: [method, path, route, backend, status, duration, bytes,
               client_ip, request_id, trace_id, span_id, host, user_agent]
      field_policies:
        client_ip: hash       # omit, plain, or hash
      headers:
        - name: X-Tenant-ID
          policy: plain
        - name: Authorization # policy omitted: always [REDACTED]
      query:
        - name: account
          policy: hash
        - name: access_token  # policy omitted: always [REDACTED]
      hash:
        algorithm: hmac_sha256 # hmac_sha256 (default) or salted sha256
        secret_env: RELAY_ACCESS_LOG_HASH_SECRET
        # secret_file: /run/secrets/access-log-hash
    otlp:
      enabled: true
      exporter: otlp_grpc     # otlp_grpc or otlp_http
      endpoint: https://otel-collector:4317
      headers_env: RELAY_OTLP_LOG_HEADERS # comma-separated key=value
      # headers_file: /run/secrets/otlp-log-headers
      queue_size: 2048
      batch_size: 512
      batch_timeout: 1s
      export_timeout: 10s
      service_name: relay
```

Policies apply independently to every built-in or selected field. Hashes are
stable for correlation and use a secret loaded from env/file; raw secrets are
not retained in YAML. Sensitive names (authorization, cookies, API keys,
tokens, passwords, and secrets) default to the literal `[REDACTED]`, and
validation rejects `plain` for them. Full token/cookie values are therefore
never emitted. OTLP is additive: stdout/file remains active. Its request path
never blocks on the collector; a full bounded queue drops records and increments
`relay_otlp_log_dropped_total`. Reload prepares the new exporter before publish,
then drains and shuts down the retired batch pipeline.

### `prometheus`

| Field | Default | Description |
| --- | --- | --- |
| `prometheus.path` | `/_relay/metrics/prometheus` | Prometheus scrape path. |
| `prometheus.allowed_cidrs` | loopback | Extra source ranges (real TCP peer) allowed to scrape metrics. Public CIDRs are rejected. |

### `tracing`

| Field | Default | Description |
| --- | --- | --- |
| `enabled` | `false` | Enable OpenTelemetry tracing. |
| `exporter` | — | `otlp_grpc`, `otlp_http`, or `stdout`. |
| `endpoint` | SDK default | Collector address. |
| `sample_rate` | `1.0` | Fraction of traces sampled (0.0–1.0). |
| `service_name` | `relay` | Service name reported to the collector. |

Logging (including OTLP logs) and tracing are hot-reloadable. Relay initializes
the complete new log handler/writer and telemetry providers/exporters before
changing live state. A
failure keeps the previous observability configuration and request-handling
state intact. After a successful atomic swap, the old writer is flushed and the
old exporter is shut down only after requests/spans already using them drain.

### `fabric`

| Field | Description |
| --- | --- |
| `fabric.enabled`, `fabric.service_name`, `fabric.queue_size` | Algoryn Fabric protobuf telemetry. |

---

## reload and include

### `reload`

| Field | Description |
| --- | --- |
| `watch` | Watch the root config and every transitive file-based include, then hot-reload on change (`enabled` is an alias). |
| `debounce` | Debounce window (required when `watch` is on). |

The watched file set is replaced after each successful reload, so adding or
removing includes takes effect automatically. Directory watches make atomic
file replacements safe. If a reload refers to an include that does not exist
yet, Relay keeps serving the last valid config and watches the nearest existing
parent directory so it can retry when the file appears. A successfully reloaded
`debounce` value applies to subsequent changes.

Reloads are transactional through load, environment/secret resolution,
validation, runtime build, server apply, and observability initialization. The
process keeps one Prometheus registry and collector for its lifetime, so
counters and existing series do not reset when states are replaced. Monitor
`relay_config_reload_total{result,stage}` and
`relay_config_last_successful_reload_timestamp_seconds`; stage values are the
bounded set `load`, `resolve`, `validate`, `build`, `apply`, and
`observability` (error text is logged, never used as a metric label).

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
