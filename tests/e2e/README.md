# Relay end-to-end tests

The runtime suite builds Relay and an in-repository upstream fixture, then starts
an isolated Docker Compose project. It covers:

- basic HTTP proxying;
- reloading a changed `include` file;
- Redis unavailable with default fail-closed and explicit `fail_open: true`;
- an upstream requiring a client certificate, with active health checks;
- ACME configuration validation in a read-only container, including safe
  rejection when `acme_cache_dir` is missing.

The include test sends `SIGHUP` after changing the included file. Relay currently
watches only the root config file, so the test deliberately does not claim that
transitive file watching is supported.

Requirements: Docker Engine with Compose v2, `curl`, and `openssl`.

```sh
bash tests/e2e/run.sh
```

Set `E2E_PORT` if port `18088` is already occupied. The script uses a unique
Compose project, generates one-day test certificates, prints service logs on
failure, and removes all containers and temporary files on exit. Runtime
services do not call public endpoints; image pulls are the only network access.
All directly introduced images use immutable digests.

The chart check requires Go and Helm `v3.18.6`:

```sh
HELM_VERSION=v3.18.6 bash tests/e2e/helm.sh
```

It runs strict `helm lint`, renders the complete chart, extracts `relay.yaml`
from the rendered ConfigMap, validates it with Relay itself, and checks the
rendered read-only-root and config-checksum safeguards. ACME checks use
`relay.invalid` and `-validate`; they never request a certificate or contact
Let's Encrypt.
