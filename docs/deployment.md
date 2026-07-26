# Deploying Relay

Relay is a single, stateless Go binary driven by one config file. The same build
runs a small single-instance gateway on a VPS and a horizontally-scaled fleet in
Kubernetes — you pick the packaging, not a different product.

- [Track A — VPS / bare host](#track-a--vps--bare-host)
- [Track B — Kubernetes (Helm)](#track-b--kubernetes-helm)
- [Gateway API integration](#gateway-api-integration)
- [Scaling & distributed deployments](#scaling--distributed-deployments)
- [Production checklist](#production-checklist)

---

## Track A — VPS / bare host

### Option 1: binary + systemd

Build (or download a release), install, and run under systemd with the hardened
unit in [`deploy/systemd/relay.service`](../deploy/systemd/relay.service):

```bash
make build                                   # produces bin/relay
sudo useradd --system --no-create-home --shell /usr/sbin/nologin relay
sudo install -m 0755 bin/relay /usr/local/bin/relay
sudo install -d -o relay -g relay /etc/relay
sudo install -m 0640 -o relay -g relay my-config.yaml /etc/relay/relay.yaml
sudo cp deploy/systemd/relay.service /etc/systemd/system/relay.service
sudo systemctl daemon-reload && sudo systemctl enable --now relay
journalctl -u relay -f
```

Secrets go in `/etc/relay/relay.env` (an `EnvironmentFile`), or use file-based
secrets (`secret_file`, `client_secret_file`, …) pointing at files only `relay`
can read.

### Option 2: Docker Compose

Use [`deploy/docker-compose.prod.yaml`](../deploy/docker-compose.prod.yaml),
which pulls the published image and mounts your config:

```bash
RELAY_VERSION=0.1.0 docker compose -f deploy/docker-compose.prod.yaml up -d
```

### TLS on a VPS

Relay can obtain and renew certificates automatically via ACME/Let's Encrypt — no
extra proxy needed:

```yaml
listener:
  https:
    port: 443
    tls:
      mode: auto
      domains: [api.example.com]
      acme_cache_dir: /etc/relay/tls/acme
```

Or terminate TLS with `mode: manual` and your own cert/key (hot-rotated on reload).

---

## Track B — Kubernetes (Helm)

The chart lives in [`deploy/helm/relay`](../deploy/helm/relay).

```bash
helm install relay ./deploy/helm/relay \
  --set replicaCount=2 \
  --set-file config=./my-relay.yaml        # or edit the `config` value inline
```

What the chart provides: Deployment, Service, ConfigMap (your Relay config),
optional Secret, ServiceAccount, optional HPA / PodDisruptionBudget / ServiceMonitor,
liveness (`/_relay/health`) and readiness (`/_relay/ready`) probes, and a hardened
security context (non-root uid 10001, read-only root filesystem, dropped caps).

### Config and secrets

- **Config**: set the `config` value (rendered into a ConfigMap and mounted at
  `/etc/relay/relay.yaml`), or point `existingConfigMap` at your own. Pods roll
  automatically when the rendered config changes.
- **Env secrets**: `secrets: { JWT_SECRET: "..." }` creates a Secret exposed via
  `envFrom`; or reference one with `existingSecret`.
- **File secrets (recommended)**: mount a Secret as files with `extraVolumes` /
  `extraVolumeMounts` and reference them from the config with `secret_file`,
  `client_secret_file`, `redis_url_file`, or `listener.admin.token_file`.

### Metrics / Prometheus

Relay's metrics endpoints are **loopback-only by default**. To let an in-cluster
Prometheus (or a `ServiceMonitor`) scrape them, allow the scraper's source range
in the config:

```yaml
observability:
  prometheus:
    allowed_cidrs: ["10.0.0.0/8"]   # your pod / Prometheus CIDR
```

Then enable the ServiceMonitor:

```bash
helm upgrade relay ./deploy/helm/relay --set metrics.serviceMonitor.enabled=true
```

### Dashboards & alerts

Relay ships a Grafana dashboard (RED signals + resilience metrics) and a set of
Prometheus alerting rules:

- **Dashboard**: [`deploy/helm/relay/dashboards/relay-dashboard.json`](../deploy/helm/relay/dashboards/relay-dashboard.json) — import into Grafana, or ship via the chart with `--set metrics.dashboards.enabled=true` (Grafana sidecar).
- **Alerts**: [`deploy/helm/relay/files/prometheus-rules.yaml`](../deploy/helm/relay/files/prometheus-rules.yaml) — load into a plain Prometheus (`rule_files`), or ship a `PrometheusRule` with `--set metrics.prometheusRule.enabled=true`. Covers error rate, p99 latency, backend health, open circuit breakers, bulkhead rejections, retry-budget exhaustion, and target down. See [`deploy/prometheus/README.md`](../deploy/prometheus/README.md).

---

## Gateway API integration

Relay is a data-plane gateway, not a Gateway API controller. The idiomatic
pattern is to let your cluster's Gateway API implementation route traffic to
Relay's Service; Relay does the gateway work and proxies to your backends. See
[`deploy/gateway-api`](../deploy/gateway-api) for `Gateway` and `HTTPRoute`
examples.

---

## Scaling & distributed deployments

Relay handles every request statelessly, so it scales horizontally with no
coordination: run N replicas behind the Service (or an HPA).

| Concern | Single instance | Multiple instances |
| --- | --- | --- |
| Rate limiting | in-memory (per instance) | set `store: redis` for a shared limit |
| Response cache | in-memory (per instance) | per-instance is fine; each caches independently |
| Config | one file / ConfigMap | same file/ConfigMap on every replica; rolling restart to change |
| Backend discovery | static URLs | a Kubernetes `Service` DNS name load-balances pods |
| TLS | ACME or manual in Relay | usually terminated at the LB / Gateway |

The only state that must be shared for correctness across replicas is distributed
rate limiting — point the `rate_limit` middleware at Redis. Everything else is
per-instance by design.

---

## Production checklist

- [ ] Timeouts set (`listener.timeouts.read/write/idle/read_header`).
- [ ] Overload protection: `listener.max_concurrent_requests` and/or per-backend `bulkhead`.
- [ ] Retries bounded with a `retry.budget_ratio` to avoid retry storms.
- [ ] Health/readiness probes wired (`/_relay/health`, `/_relay/ready`).
- [ ] Metrics scrape allowed (`observability.prometheus.allowed_cidrs`) and dashboards/alerts in place.
- [ ] Secrets provided via env or `*_file` — never committed to the config.
- [ ] TLS configured (ACME auto, manual, or terminated upstream) with a hardened `min_version`.
- [ ] Admin API restricted (`listener.admin.allowed_cidrs` + `token_env`/`token_file`).
- [ ] For multiple replicas: `store: redis` for rate limiting.
