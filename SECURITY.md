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
- **Inbound mTLS / TLS version**: set `listener.https.tls.min_version: "1.3"` for
  the strongest default, or rely on the hardened TLS 1.2 cipher list. For
  zero-trust, set `client_ca_file` (and optionally `client_auth`) to require
  client certificates.

## Release artifact verification

Releases ship a CycloneDX SBOM per archive and a cosign (keyless) signature of
the checksums file and the Docker image(s). Verify before deploying:

```sh
cosign verify-blob --certificate checksums.txt.pem \
  --signature checksums.txt.sig checksums.txt
cosign verify algoryn/relay:<version> \
  --certificate-identity-regexp '.*' --certificate-oidc-issuer-regexp '.*'
```

Signing runs in CI and requires the `cosign`/`syft` binaries and OIDC token
permission (`id-token: write` in GitHub Actions).
