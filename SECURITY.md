# Security Policy

## Reporting a vulnerability

Please report security issues privately. Do not open a public issue for a
suspected vulnerability.

- Email: jbluedev@gmail.com
- Include: affected version/commit, a description, reproduction steps, and impact.

You will receive an acknowledgement, and we will work with you on a fix and a
coordinated disclosure timeline.

## Supported versions

Relay is pre-1.0; security fixes are applied to `main` and the latest release.

## Hardening notes for operators

- **TLS**: terminate TLS at Relay (`listener.https`) or at a trusted load
  balancer. Auto/ACME mode (`mode: auto`) is single-node — for multiple replicas
  use `mode: manual` with externally-managed certificates.
- **Trusted proxies**: set `listener.trusted_proxies` to the addresses of the
  proxies in front of Relay. Client IP is taken from `X-Forwarded-For` only when
  the immediate peer is trusted. Admin and metrics endpoints are always gated on
  the real TCP peer.
- **Identity headers**: Relay strips its managed identity headers and the
  `X-Forwarded-*` family from inbound requests. Add any app-specific identity
  headers your backends trust to `listener.strip_request_headers`.
- **JWT**: prefer RS256 with a JWKS endpoint over `https`, and set `issuer` /
  `audience`. Keep HS256 secrets >= 32 bytes and supply them via env vars.
- **Admin/metrics**: keep them on the loopback/allowlist or a separate internal
  network. The Prometheus endpoint is loopback-gated by default.
- **Secrets**: provide secrets via environment variables (`*_env` fields), never
  in plaintext config.
