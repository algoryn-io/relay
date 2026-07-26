# Prometheus alerting rules

The canonical Relay alerting rules live in
[`../helm/relay/files/prometheus-rules.yaml`](../helm/relay/files/prometheus-rules.yaml)
so the Helm chart and standalone Prometheus share a single source of truth.

## Plain Prometheus (no Operator)

Copy the rules file next to your `prometheus.yml` and reference it:

```yaml
# prometheus.yml
rule_files:
  - relay-rules.yaml   # copy of helm/relay/files/prometheus-rules.yaml
```

## Prometheus Operator

Enable the equivalent `PrometheusRule` via the Helm chart:

```bash
helm upgrade relay ./deploy/helm/relay --set metrics.prometheusRule.enabled=true
```

## Alerts

| Alert | Severity | Fires when |
| --- | --- | --- |
| `RelayHighErrorRate` / `...Critical` | warning / critical | 5xx ratio > 5% / 20% for 5m |
| `RelayHighLatencyP99` | warning | p99 request latency > 1s for 10m |
| `RelayBackendNoHealthyInstances` | critical | a backend has 0 healthy instances for 5m |
| `RelayCircuitBreakerOpen` | warning | a backend circuit breaker is open for 5m |
| `RelayBulkheadRejecting` | warning | a backend bulkhead sheds requests for 10m |
| `RelayRetryBudgetExhausted` | warning | retries suppressed by the budget for 10m |
| `RelayConfigReloadFailing` | warning | a reload failure remains visible for 2m |
| `RelayRateLimitRedisUnavailable` | critical | the latest Redis checks fail for 2m |
| `RelayRateLimitRedisDegraded` | warning | fail-open Redis degradation lasts 5m |
| `RelayRateLimitFailOpenBypass` | warning | fail-open bypasses persist for 2m |
| `RelayRateLimitMemoryEvictionPressure` | warning | evictions exceed 0.1/s for 10m |
| `RelayTargetDown` | critical | a Relay scrape target is down for 5m |

Operational response procedures are documented in
[`../../docs/operational-events-runbook.md`](../../docs/operational-events-runbook.md).
