#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: smoke_otlp_export.sh [options] [-- <binary args...>]

Options:
  -b, --binary PATH     Run the binary at PATH instead of "cargo run -p rpp-node".
  -m, --mode MODE       Runtime mode to exercise (node, wallet, hybrid, validator).
      --subcommand CMD  Optional subcommand to invoke after the runtime mode.
  -s, --expect SIGNAL   Override the telemetry span/name expected in collector logs.
  -h, --help            Show this message.

Additional arguments after "--" are forwarded verbatim to the binary and take
precedence over OTLP_NODE_ARGS/default arguments.
USAGE
}

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required to run the OTLP smoke test" >&2
  exit 1
fi

MODE="node"
CUSTOM_EXPECT=""
BINARY_OVERRIDE=""
SUBCOMMAND=""
FORWARDED_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    -b|--binary)
      if [[ $# -lt 2 ]]; then
        echo "--binary requires a path argument" >&2
        exit 1
      fi
      BINARY_OVERRIDE="$2"
      shift 2
      ;;
    -m|--mode)
      if [[ $# -lt 2 ]]; then
        echo "--mode requires an argument" >&2
        exit 1
      fi
      MODE="$2"
      shift 2
      ;;
    -s|--expect)
      if [[ $# -lt 2 ]]; then
        echo "--expect requires a value" >&2
        exit 1
      fi
      CUSTOM_EXPECT="$2"
      shift 2
      ;;
    --subcommand)
      if [[ $# -lt 2 ]]; then
        echo "--subcommand requires a value" >&2
        exit 1
      fi
      SUBCOMMAND="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      FORWARDED_ARGS=("$@")
      break
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

case "${MODE}" in
  node|wallet|hybrid|validator)
    ;;
  *)
    echo "unsupported mode: ${MODE}" >&2
    exit 1
    ;;
esac

EXPECTED_SIGNAL="${CUSTOM_EXPECT}"
if [[ -z "${EXPECTED_SIGNAL}" ]]; then
  case "${MODE}" in
    wallet)
      EXPECTED_SIGNAL="node.telemetry.init"
      ;;
    *)
      EXPECTED_SIGNAL="node.telemetry.init"
      ;;
  esac
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

DEFAULT_ARGS=(
  "--telemetry-endpoint" "http://127.0.0.1:4317"
  "--telemetry-sample-interval" "2"
  "--log-json"
)

if [[ ${#FORWARDED_ARGS[@]} -gt 0 ]]; then
  NODE_ARGS=("${FORWARDED_ARGS[@]}")
elif [[ -n "${OTLP_NODE_ARGS:-}" ]]; then
  # shellcheck disable=SC2206
  NODE_ARGS=(${OTLP_NODE_ARGS})
else
  NODE_ARGS=("${DEFAULT_ARGS[@]}")
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
COMMAND_PREFIX=()
if [[ -n "${BINARY_OVERRIDE}" ]]; then
  COMMAND_PREFIX=("${BINARY_OVERRIDE}")
elif [[ -n "${RPP_NODE_BIN:-}" ]]; then
  COMMAND_PREFIX=("${RPP_NODE_BIN}")
else
  COMMAND_PREFIX=("cargo" "run" "--quiet" "-p" "rpp-node" "--")
fi

MODE_ARGS=("${MODE}")
if [[ -n "${SUBCOMMAND}" ]]; then
  MODE_ARGS+=("${SUBCOMMAND}")
fi

RUN_COMMAND=("${COMMAND_PREFIX[@]}" "${MODE_ARGS[@]}")

set +e
timeout "${SMOKE_TIMEOUT}" "${RUN_COMMAND[@]}" "${NODE_ARGS[@]}" >"${NODE_LOG}" 2>&1
STATUS=$?
set -e

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

if ! grep -q "${EXPECTED_SIGNAL}" <<<"${COLLECTOR_LOGS}"; then
  echo "failed to observe exported spans in collector output" >&2
  exit 1
fi

echo "OTLP export smoke test completed successfully" >&2
