#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"
chart="$repo_root/deploy/helm/relay"
values="$script_dir/fixtures/helm-values.yaml"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/relay-helm.XXXXXX")"
trap 'rm -rf "$work_dir"' EXIT

expected_helm_version="${HELM_VERSION:-v3.18.6}"
actual_helm_version="$(helm version --template '{{.Version}}')"
if [[ "$actual_helm_version" != "$expected_helm_version" ]]; then
  printf 'Helm %s is required; found %s\n' "$expected_helm_version" "$actual_helm_version" >&2
  exit 1
fi

helm lint --strict "$chart" -f "$values"
helm template relay-e2e "$chart" -f "$values" >"$work_dir/manifests.yaml"
helm template relay-e2e "$chart" -f "$values" \
  --show-only templates/configmap.yaml >"$work_dir/configmap.yaml"

awk '
  /^  relay.yaml: \|/ { config = 1; next }
  config && /^    / { sub(/^    /, ""); print; next }
  config { exit }
' "$work_dir/configmap.yaml" >"$work_dir/relay.yaml"

[[ -s "$work_dir/relay.yaml" ]] || {
  printf 'Rendered ConfigMap did not contain relay.yaml\n' >&2
  exit 1
}

go run "$repo_root/cmd/relay" -config "$work_dir/relay.yaml" -validate

awk '
  /readOnlyRootFilesystem: true/ { readonly = 1 }
  /checksum\/config:/ { checksum = 1 }
  END { exit !(readonly && checksum) }
' "$work_dir/manifests.yaml" || {
  printf 'Rendered workload lost read-only root or config checksum safeguards\n' >&2
  exit 1
}

printf 'Helm lint, template, and rendered Relay config validation passed.\n'
