# Relay with the Kubernetes Gateway API

Relay is a config-driven data-plane gateway, **not** a Gateway API controller — it
does not watch `Gateway`/`HTTPRoute` CRDs. Instead, these examples show the
common, low-friction integration: an existing Gateway API implementation in your
cluster (Envoy Gateway, Istio, NGINX Gateway Fabric, Cilium, …) routes north-south
traffic to Relay's `Service`, and Relay does the API-gateway work (auth, rate
limiting, retries, caching, gRPC, …) before proxying to your backends.

```
client ──▶ Gateway (Gateway API impl) ──▶ HTTPRoute ──▶ Relay Service ──▶ Relay ──▶ your backends
```

This keeps Relay's lightweight, single-binary identity while fitting cleanly into a
Gateway-API-managed edge.

## Files

- `gateway.yaml` — a `Gateway` with an HTTP listener, bound to a `GatewayClass`
  provided by your Gateway API implementation (edit `gatewayClassName`).
- `httproute.yaml` — an `HTTPRoute` that forwards a hostname to the Relay
  `Service` created by the Helm chart (`deploy/helm/relay`).

## Apply

```bash
# 1. Deploy Relay (Service name defaults to the release name).
helm install relay ./deploy/helm/relay

# 2. Point a Gateway at it. Edit gatewayClassName and hostnames first.
kubectl apply -f deploy/gateway-api/gateway.yaml
kubectl apply -f deploy/gateway-api/httproute.yaml
```

The `HTTPRoute` here does host-level routing only and delegates all path/method
routing, auth and policy to Relay's own config. If you prefer, you can also push
finer-grained rules into the `HTTPRoute` — but Relay's config is the source of
truth for gateway behavior.
