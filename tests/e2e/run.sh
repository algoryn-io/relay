#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"
runtime_dir="$(mktemp -d "${TMPDIR:-/tmp}/relay-e2e.XXXXXX")"

export E2E_RUNTIME_DIR="$runtime_dir"
export E2E_PROJECT_NAME="relay-e2e-${GITHUB_RUN_ID:-local}-$$"
export E2E_PORT="${E2E_PORT:-18088}"
compose=(docker compose -f "$script_dir/docker-compose.yml")
base_url="http://127.0.0.1:${E2E_PORT}"

cleanup() {
  status=$?
  if (( status != 0 )); then
    "${compose[@]}" logs --no-color || true
  fi
  "${compose[@]}" --profile validation down --volumes --remove-orphans --rmi local >/dev/null 2>&1 || true
  rm -rf "$runtime_dir"
  exit "$status"
}
trap cleanup EXIT

fail() {
  printf 'E2E failure: %s\n' "$*" >&2
  return 1
}

assert_body() {
  local path=$1 expected=$2 actual
  actual="$(curl --fail --silent --show-error --max-time 3 "$base_url$path")"
  [[ "$actual" == "$expected" ]] ||
    fail "$path returned body '$actual'; expected '$expected'"
}

assert_status() {
  local path=$1 expected=$2 actual
  actual="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 3 "$base_url$path")"
  [[ "$actual" == "$expected" ]] ||
    fail "$path returned status $actual; expected $expected"
}

wait_for_body() {
  local path=$1 expected=$2
  for _ in {1..40}; do
    if [[ "$(curl --silent --max-time 1 "$base_url$path" || true)" == "$expected" ]]; then
      return
    fi
    sleep 0.25
  done
  fail "$path did not return '$expected' before timeout"
}

generate_certificates() {
  local cert_dir="$runtime_dir/certs"
  mkdir -p "$cert_dir"
  openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
    -subj "/CN=relay-e2e-ca" \
    -keyout "$cert_dir/ca.key" -out "$cert_dir/ca.crt" >/dev/null 2>&1

  openssl req -newkey rsa:2048 -sha256 -nodes \
    -subj "/CN=upstream-mtls" \
    -keyout "$cert_dir/server.key" -out "$cert_dir/server.csr" >/dev/null 2>&1
  printf 'subjectAltName=DNS:upstream-mtls\nextendedKeyUsage=serverAuth\n' >"$cert_dir/server.ext"
  openssl x509 -req -sha256 -days 1 \
    -in "$cert_dir/server.csr" -CA "$cert_dir/ca.crt" -CAkey "$cert_dir/ca.key" \
    -CAcreateserial -extfile "$cert_dir/server.ext" \
    -out "$cert_dir/server.crt" >/dev/null 2>&1

  openssl req -newkey rsa:2048 -sha256 -nodes \
    -subj "/CN=relay" \
    -keyout "$cert_dir/client.key" -out "$cert_dir/client.csr" >/dev/null 2>&1
  printf 'extendedKeyUsage=clientAuth\n' >"$cert_dir/client.ext"
  openssl x509 -req -sha256 -days 1 \
    -in "$cert_dir/client.csr" -CA "$cert_dir/ca.crt" -CAkey "$cert_dir/ca.key" \
    -CAcreateserial -extfile "$cert_dir/client.ext" \
    -out "$cert_dir/client.crt" >/dev/null 2>&1
  chmod 0644 "$cert_dir"/*
}

docker info >/dev/null 2>&1 ||
  fail "Docker daemon is unavailable"
command -v openssl >/dev/null ||
  fail "openssl is required"

mkdir -p "$runtime_dir/config"
cp "$script_dir/fixtures/config/relay.yaml" "$runtime_dir/config/relay.yaml"
cp "$script_dir/fixtures/config/base.yaml" "$runtime_dir/config/base.yaml"
cp "$script_dir/fixtures/config/reload-v1.yaml" "$runtime_dir/config/reload.yaml"
generate_certificates

printf 'Starting isolated Compose stack...\n'
"${compose[@]}" up --build --detach --wait --wait-timeout 60

printf 'Checking basic proxy traffic...\n'
assert_body "/basic" "v1:/basic"

printf 'Checking automatic included-config reload...\n'
assert_body "/reload" "v1:/reload"
cp "$script_dir/fixtures/config/reload-v2.yaml" "$runtime_dir/config/reload.yaml"
wait_for_body "/reload" "v2:/reload"

printf 'Checking mTLS upstream and active health checks...\n'
wait_for_body "/mtls" "mtls:/mtls"

printf 'Checking Redis fail-closed and explicit fail-open...\n'
assert_body "/redis/closed" "v1:/redis/closed"
assert_body "/redis/open" "v1:/redis/open"
"${compose[@]}" stop redis
assert_status "/redis/closed" "503"
assert_status "/redis/open" "200"

printf 'Checking ACME configuration on a read-only root filesystem...\n'
"${compose[@]}" --profile validation run --rm --no-deps acme-validate
"${compose[@]}" --profile validation run --rm --no-deps acme-validate \
  -config /etc/relay/acme/distributed.yaml -validate
if output="$("${compose[@]}" --profile validation run --rm --no-deps acme-validate \
  -config /etc/relay/acme/missing-cache.yaml -validate 2>&1)"; then
  fail "ACME configuration without a cache backend was accepted"
fi
[[ "$output" == *"acme_cache.backend"* ]] ||
  fail "invalid ACME config failed without reporting acme_cache.backend"

printf 'Relay E2E runtime suite passed.\n'
