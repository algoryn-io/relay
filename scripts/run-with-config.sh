#!/usr/bin/env bash
# Run Relay with a given YAML config (sets RELAY_CONFIG). Run from repo root recommended.
# Usage: ./scripts/run-with-config.sh path/to/config.yaml
set -euo pipefail

if [[ $# -lt 1 ]] || [[ "${1:-}" == "-h" ]] || [[ "${1:-}" == "--help" ]]; then
	echo "Usage: $0 <path-to-config.yaml>" >&2
	echo "Example: $0 ./config/examples/api-gateway-prefix-routes.yaml" >&2
	exit 1
fi

CFG="$1"
if [[ ! -f "$CFG" ]]; then
	echo "File not found: $CFG" >&2
	exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export RELAY_CONFIG="$(cd "$(dirname "$CFG")" && pwd)/$(basename "$CFG")"
echo "RELAY_CONFIG=${RELAY_CONFIG}"
echo "Starting Relay (Ctrl+C to stop)..."
exec go run ./cmd/relay
