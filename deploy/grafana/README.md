# Grafana dashboard

The Relay dashboard JSON lives in
[`../helm/relay/dashboards/relay-dashboard.json`](../helm/relay/dashboards/relay-dashboard.json)
(single source of truth, also shipped by the Helm chart).

It covers the RED signals (request rate, errors, latency p50/p95/p99) plus
Relay's resilience metrics: upstream latency, backend health, retries and retry
budget, circuit-breaker state, and bulkhead in-flight/rejections.

## Import manually

Grafana → Dashboards → New → Import → Upload JSON file, then select your
Prometheus data source.

## GitOps / provisioning

Point a Grafana dashboard provider at the JSON, or (with the Grafana sidecar)
let the Helm chart ship it as a labeled ConfigMap:

```bash
helm upgrade relay ./deploy/helm/relay --set metrics.dashboards.enabled=true
```

The metrics endpoints are loopback-only by default — make sure
`observability.prometheus.allowed_cidrs` permits your Prometheus, otherwise there
is no data to display. See [../../docs/deployment.md](../../docs/deployment.md).
