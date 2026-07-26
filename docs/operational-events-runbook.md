# Operational events runbook

Relay emits structured transition events to its logger and, when enabled, the
Fabric `EventDispatcher`. Repeated occurrences still increment Prometheus
counters, but identical state transitions are suppressed to avoid alert and log
storms. Event payloads contain only stable codes, bounded state/stage values and
the configured Fabric service name; they never contain request keys, client
identifiers, Redis URLs, credentials or raw errors.

## Event codes and metrics

- `relay.config_reload.failed` / `.succeeded`: inspect
  `relay_config_reload_total{result,stage}`. A failed reload is transactional and
  leaves the prior configuration active.
- `relay.rate_limit.redis.degraded`: Redis failed while fail-open was enabled.
  Requests may bypass rate limiting; inspect
  `relay_rate_limit_fail_open_bypass_total`.
- `relay.rate_limit.redis.unavailable`: Redis failed for a fail-closed limiter.
  Affected requests return `503 rate_limit_unavailable`.
- `relay.rate_limit.redis.recovered`: the first successful check after either
  Redis failure state.
- `relay.rate_limit.fail_open_bypass`: at least one request bypassed enforcement.
  The event is emitted once per outage, while every bypass increments its
  counter.
- `relay.rate_limit.memory_eviction_pressure`: an in-process store reached its
  configured bucket capacity. Every eviction increments
  `relay_rate_limit_memory_evictions_total`.

`relay_operational_events_total{code}` counts emitted transitions.
`relay_rate_limit_redis_checks_total{result}` counts every Redis check, and
`relay_rate_limit_redis_state` reports aggregate state (`0` healthy, `1`
degraded fail-open, `2` unavailable fail-closed).

## Response procedures

### Configuration reload failures

1. Identify the bounded `stage` (`load`, `resolve`, `validate`, `build`, `apply`
   or `observability`).
2. Validate the candidate configuration in a safe environment and check Secret
   mounts/environment references without copying their values into tickets.
3. Correct the source file. The watcher retries after a relevant file change,
   or send `SIGHUP`.
4. Confirm a `.succeeded` transition and a newer
   `relay_config_last_successful_reload_timestamp_seconds`.

### Redis degraded or unavailable

1. Check Redis reachability, TLS trust, pool saturation and latency from the
   Relay network namespace. Do not print connection URLs because they may embed
   credentials.
2. Confirm whether affected middleware is configured `fail_open`. Treat bypass
   growth as an enforcement gap and unavailable responses as an availability
   incident.
3. Restore Redis and confirm `relay_rate_limit_redis_available == 1` plus a
   `.recovered` transition.
4. If failures recur, investigate Redis capacity/network health before changing
   the 100 ms request-path timeout.

### Memory eviction pressure

1. Compare the eviction rate with `relay_rate_limit_memory_buckets` and the
   configured `memory_max_buckets`.
2. Check whether key cardinality increased unexpectedly. Bucket keys are
   intentionally absent from telemetry; use aggregate traffic and route data.
3. Increase the per-pod cap only within the pod memory budget, reduce idle TTL
   where safe, or move to Redis when replicas need a shared limit.

## Alerts and dashboards

The canonical Prometheus rules are in
`deploy/helm/relay/files/prometheus-rules.yaml`. The Grafana dashboard includes
Redis availability, bypass/error rates, reload failures, memory evictions and
annotations from transition counters. Enable both Helm resources with:

```bash
helm upgrade relay ./deploy/helm/relay \
  --set metrics.prometheusRule.enabled=true \
  --set metrics.dashboards.enabled=true
```
