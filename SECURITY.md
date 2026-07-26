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

## Static application security testing

[`gosec`](https://github.com/securego/gosec) is Relay's baseline SAST engine. CI
runs a pinned version, publishes its SARIF output to GitHub Code Scanning, and
fails on unsuppressed findings. Run the same checks locally with `make security`.
Suppressions must name the specific rule at the affected line and explain why
the reported construct is safe.

Semgrep is intentionally not adopted: its Go security rules would overlap with
the baseline and add a redundant SAST engine without a distinct coverage goal.
This decision can be revisited if a concrete, non-overlapping ruleset is needed.

## Hardening notes for operators

- **TLS**: terminate TLS at Relay (`listener.https`) or at a trusted load
  balancer. Auto/ACME mode (`mode: auto`) is single-node — for multiple replicas
  use `mode: manual` with externally-managed certificates.
- **Trusted proxies**: set `listener.trusted_proxies` to the addresses of the
  proxies in front of Relay. The client IP is resolved from `X-Forwarded-For` only
  when the immediate peer is trusted, walking the chain right-to-left and skipping
  trusted hops (a client cannot spoof its IP by pre-seeding the header). Leave it
  empty when Relay is directly internet-facing so `X-Forwarded-For` is ignored.
  IP-based controls (`ip_filter`, `by: ip` rate limiting) depend on this being set
  correctly. Admin and metrics endpoints are always gated on the real TCP peer.
- **Identity headers**: Relay strips its managed identity headers
  (`X-Authenticated-Sub`, `X-Token-Scope`, ...) and the `X-Forwarded-*` family from
  inbound requests. Add any app-specific identity headers your backends trust to
  `listener.strip_request_headers`. When using `ext_authz` `copy_headers`, those
  are stripped from the inbound request before the authorizer's values are applied.
- **External authorization data**: `ext_authz` sends inbound headers only through
  the explicit `forward_headers` allowlist, including in metadata mode. Avoid
  allowlisting `Authorization`, cookies, or API-key headers unless required.
  Original-body mode buffers only the configured maximum, never reads streaming
  or upgrade/WebSocket bodies, and replays accepted bodies unchanged upstream.
- **Response cache**: the `cache` middleware never stores or serves a response to
  an authenticated request (`Authorization`/`Cookie`) unless the origin marks it
  `public`/`s-maxage`, so one user's data is never returned to another. Still,
  place `cache` after auth middleware in a route's pipeline and prefer explicit
  `Cache-Control` on cacheable endpoints.
- **JWT**: prefer RS256 with a JWKS endpoint over `https`, and set `issuer` /
  `audience`. Keep HS256 secrets >= 32 bytes and supply them via env vars.
- **Admin/metrics**: keep them on the loopback/allowlist or a separate internal
  network. The metrics/Prometheus endpoints are loopback-gated by default; allow a
  scraper explicitly with `observability.prometheus.allowed_cidrs`.
- **Secrets**: provide secrets via environment variables (`*_env` fields) or
  mounted files (`*_file` fields, e.g. Kubernetes Secret volumes), never in
  plaintext config.
- **Inbound mTLS / TLS version**: set `listener.https.tls.min_version: "1.3"` for
  the strongest default, or rely on the hardened TLS 1.2 cipher list. For
  zero-trust, set `client_ca_file` (and optionally `client_auth`) to require
  client certificates.

## Release artifact verification

Releases are built and signed in CI (`.github/workflows/release.yml`) and ship
three layers of supply-chain metadata:

- **SBOM** (CycloneDX, per archive) — *what is inside* each artifact.
- **cosign keyless signature** of the checksums file and the Docker image(s) —
  *who signed* them (Sigstore/Fulcio/Rekor, OIDC identity).
- **SLSA build provenance** attestations for the release binaries and checksums —
  *how and where* they were built.

Verify before deploying:

```sh
# Signature of the checksums file.
cosign verify-blob --certificate checksums.txt.pem \
  --signature checksums.txt.sig checksums.txt

# Container image signature.
cosign verify algoryn/relay:<version> \
  --certificate-identity-regexp '.*' --certificate-oidc-issuer-regexp '.*'

# SLSA build provenance (GitHub attestations).
gh attestation verify relay_<version>_linux_amd64.tar.gz --repo algoryn-io/relay
```

Signing and attestation run in CI and require the `cosign`/`syft` binaries and
OIDC token permission (`id-token: write` / `attestations: write`).
