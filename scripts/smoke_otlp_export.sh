#!/usr/bin/env bash
set -euo pipefail

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required to run the OTLP smoke test" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COLLECTOR_CONFIG="${SCRIPT_DIR}/otel-collector-config.yaml"
if [[ ! -f "${COLLECTOR_CONFIG}" ]]; then
  echo "collector configuration not found at ${COLLECTOR_CONFIG}" >&2
  exit 1
fi

COLLECTOR_IMAGE="${OTLP_COLLECTOR_IMAGE:-otel/opentelemetry-collector-contrib:0.97.0}"
COLLECTOR_NAME="${OTLP_COLLECTOR_NAME:-rpp-node-otel-smoke}"
SMOKE_TIMEOUT="${OTLP_SMOKE_TIMEOUT:-20}"
NODE_ARGS=("--telemetry-endpoint" "http://127.0.0.1:4317" "--telemetry-sample-interval" "2" "--log-json")
if [[ -n "${OTLP_NODE_ARGS:-}" ]]; then
  # shellcheck disable=SC2206
  NODE_ARGS=(${OTLP_NODE_ARGS})
fi

if docker ps --format '{{.Names}}' | grep -q "^${COLLECTOR_NAME}$"; then
  echo "collector container ${COLLECTOR_NAME} is already running" >&2
  exit 1
fi

docker run \
  --rm \
  --detach \
  --name "${COLLECTOR_NAME}" \
  --publish 4317:4317 \
  --volume "${COLLECTOR_CONFIG}:/etc/otelcol/config.yaml:ro" \
  "${COLLECTOR_IMAGE}" \
  --config=/etc/otelcol/config.yaml >/dev/null

cleanup() {
  docker rm -f "${COLLECTOR_NAME}" >/dev/null 2>&1 || true
  rm -f "${NODE_LOG}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

NODE_LOG="$(mktemp -t rpp-node-otel.XXXXXX.log)"
STATUS=0
if [[ -n "${RPP_NODE_BIN:-}" ]]; then
  set +e
  timeout "${SMOKE_TIMEOUT}" "${RPP_NODE_BIN}" "${NODE_ARGS[@]}" >"${NODE_LOG}" 2>&1
  STATUS=$?
  set -e
else
  set +e
  timeout "${SMOKE_TIMEOUT}" cargo run --quiet -p rpp-node -- "${NODE_ARGS[@]}" >"${NODE_LOG}" 2>&1
  STATUS=$?
  set -e
fi

if [[ ${STATUS} -ne 0 && ${STATUS} -ne 124 ]]; then
  cat "${NODE_LOG}" >&2
  echo "node execution failed with status ${STATUS}" >&2
  exit ${STATUS}
fi

sleep 2
COLLECTOR_LOGS="$(docker logs "${COLLECTOR_NAME}")"
echo "=== collector logs ==="
echo "${COLLECTOR_LOGS}"

echo "=== node logs ==="
cat "${NODE_LOG}"

if ! grep -q "node.telemetry.init" <<<"${COLLECTOR_LOGS}"; then
  echo "failed to observe exported spans in collector output" >&2
  exit 1
fi

echo "OTLP export smoke test completed successfully" >&2
