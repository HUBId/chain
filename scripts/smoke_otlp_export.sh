#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: smoke_otlp_export.sh [options] [-- <binary args...>]

Options:
  -b, --binary PATH     Run the binary at PATH instead of "cargo run -p rpp-chain".
  -m, --mode MODE       Runtime mode to exercise (node, wallet, hybrid, validator).
      --subcommand CMD  Optional subcommand to invoke after the runtime mode.
  -s, --expect SIGNAL   Override the telemetry span/name expected in collector logs.
      --endpoint URL    Override the OTLP gRPC endpoint exposed by the smoke collector.
      --http-endpoint URL  Override the OTLP HTTP endpoint (metrics exporter).
      --auth-token TOKEN   Inject a bearer token for OTLP requests.
      --header KEY=VALUE   Append a custom OTLP header; may be provided multiple times.
      --tls-ca PATH        Trust material for TLS collectors (maps to OTEL_EXPORTER_OTLP_CERTIFICATE).
      --tls-cert PATH      Client certificate for mutual TLS collectors.
      --tls-key PATH       Client private key for mutual TLS collectors.
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
ENDPOINT_OVERRIDE=""
HTTP_ENDPOINT_OVERRIDE=""
AUTH_TOKEN=""
TLS_CA_CERT=""
TLS_CLIENT_CERT=""
TLS_CLIENT_KEY=""
declare -a EXTRA_HEADERS=()

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
    --endpoint)
      if [[ $# -lt 2 ]]; then
        echo "--endpoint requires a value" >&2
        exit 1
      fi
      ENDPOINT_OVERRIDE="$2"
      shift 2
      ;;
    --http-endpoint)
      if [[ $# -lt 2 ]]; then
        echo "--http-endpoint requires a value" >&2
        exit 1
      fi
      HTTP_ENDPOINT_OVERRIDE="$2"
      shift 2
      ;;
    --auth-token)
      if [[ $# -lt 2 ]]; then
        echo "--auth-token requires a value" >&2
        exit 1
      fi
      AUTH_TOKEN="$2"
      shift 2
      ;;
    --header)
      if [[ $# -lt 2 ]]; then
        echo "--header requires a KEY=VALUE pair" >&2
        exit 1
      fi
      EXTRA_HEADERS+=("$2")
      shift 2
      ;;
    --tls-ca)
      if [[ $# -lt 2 ]]; then
        echo "--tls-ca requires a path" >&2
        exit 1
      fi
      TLS_CA_CERT="$2"
      shift 2
      ;;
    --tls-cert)
      if [[ $# -lt 2 ]]; then
        echo "--tls-cert requires a path" >&2
        exit 1
      fi
      TLS_CLIENT_CERT="$2"
      shift 2
      ;;
    --tls-key)
      if [[ $# -lt 2 ]]; then
        echo "--tls-key requires a path" >&2
        exit 1
      fi
      TLS_CLIENT_KEY="$2"
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
  EXPECTED_SIGNAL="node.telemetry.init"
fi

case "${MODE}" in
  node)
    STARTUP_MARKERS=("node runtime started")
    PIPELINE_LABELS=("node")
    ;;
  wallet)
    STARTUP_MARKERS=("wallet runtime initialised")
    PIPELINE_LABELS=("wallet")
    ;;
  hybrid)
    STARTUP_MARKERS=("node runtime started" "wallet runtime initialised")
    PIPELINE_LABELS=("node" "wallet")
    ;;
  validator)
    STARTUP_MARKERS=("node runtime started" "wallet runtime initialised")
    PIPELINE_LABELS=("node" "wallet")
    ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COLLECTOR_CONFIG="${SCRIPT_DIR}/otel-collector-config.yaml"
if [[ ! -f "${COLLECTOR_CONFIG}" ]]; then
  echo "collector configuration not found at ${COLLECTOR_CONFIG}" >&2
  exit 1
fi

COLLECTOR_IMAGE="${OTLP_COLLECTOR_IMAGE:-otel/opentelemetry-collector-contrib:0.97.0}"
COLLECTOR_NAME="${OTLP_COLLECTOR_NAME:-rpp-node-otel-smoke}"
SMOKE_TIMEOUT="${OTLP_SMOKE_TIMEOUT:-20}"

DEFAULT_ENDPOINT="${ENDPOINT_OVERRIDE:-http://127.0.0.1:4317}"
DEFAULT_HTTP_ENDPOINT="${HTTP_ENDPOINT_OVERRIDE}"
DEFAULT_ARGS=(
  "--telemetry-endpoint" "${DEFAULT_ENDPOINT}"
  "--telemetry-sample-interval" "2"
  "--log-json"
)

if [[ -n "${DEFAULT_HTTP_ENDPOINT}" ]]; then
  DEFAULT_ARGS=("--telemetry-http-endpoint" "${DEFAULT_HTTP_ENDPOINT}" "${DEFAULT_ARGS[@]}")
fi

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
  COMMAND_PREFIX=("cargo" "run" "--quiet" "-p" "rpp-chain" "--")
fi

MODE_ARGS=("start" "--mode" "${MODE}")
if [[ -n "${SUBCOMMAND}" ]]; then
  MODE_ARGS+=("${SUBCOMMAND}")
fi

if [[ -n "${ENDPOINT_OVERRIDE}" ]]; then
  export RPP_NODE_OTLP_ENDPOINT="${ENDPOINT_OVERRIDE}"
fi
if [[ -n "${HTTP_ENDPOINT_OVERRIDE}" ]]; then
  export RPP_NODE_OTLP_HTTP_ENDPOINT="${HTTP_ENDPOINT_OVERRIDE}"
fi
if [[ -n "${AUTH_TOKEN}" ]]; then
  export RPP_NODE_OTLP_AUTH_TOKEN="${AUTH_TOKEN}"
fi
if [[ -n "${TLS_CA_CERT}" ]]; then
  export OTEL_EXPORTER_OTLP_CERTIFICATE="${TLS_CA_CERT}"
fi
if [[ -n "${TLS_CLIENT_CERT}" ]]; then
  export OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE="${TLS_CLIENT_CERT}"
fi
if [[ -n "${TLS_CLIENT_KEY}" ]]; then
  export OTEL_EXPORTER_OTLP_CLIENT_KEY="${TLS_CLIENT_KEY}"
fi
if [[ ${#EXTRA_HEADERS[@]} -gt 0 ]]; then
  old_ifs="${IFS}"
  IFS=','
  export OTEL_EXPORTER_OTLP_HEADERS="${EXTRA_HEADERS[*]}"
  IFS="${old_ifs}"
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

for marker in "${STARTUP_MARKERS[@]}"; do
  if [[ -n "${marker}" ]] && ! grep -q "${marker}" "${NODE_LOG}"; then
    echo "node logs missing expected startup marker: ${marker}" >&2
    exit 1
  fi
done

for pipeline in "${PIPELINE_LABELS[@]}"; do
  if [[ -z "${pipeline}" ]]; then
    continue
  fi
  if ! grep -Eq "pipeline=\\\"${pipeline}\\\".*started|started.*pipeline=\\\"${pipeline}\\\"" "${NODE_LOG}"; then
    echo "node logs missing pipeline marker: pipeline=\"${pipeline}\" started" >&2
    exit 1
  fi
done

if [[ "${MODE}" == "wallet" || "${MODE}" == "hybrid" ]]; then
  DIAG_ENDPOINT="${RPP_WALLET_HEALTH_ENDPOINT:-http://127.0.0.1:9942/health}"
  DIAG_CMD=("${SCRIPT_DIR}/wallet_diag.sh" "--mode" "${MODE}" "--endpoint" "${DIAG_ENDPOINT}" "--log" "${NODE_LOG}")
  if [[ -n "${AUTH_TOKEN}" ]]; then
    DIAG_CMD+=("--auth-token" "${AUTH_TOKEN}")
  fi
  "${DIAG_CMD[@]}"
fi

if ! grep -q "${EXPECTED_SIGNAL}" <<<"${COLLECTOR_LOGS}"; then
  echo "failed to observe exported spans in collector output" >&2
  exit 1
fi

python3 <<'PY' <<<"${COLLECTOR_LOGS}" || exit 1
import re
import sys

logs = sys.stdin.read()

def extract_blocks(kind):
    pattern = re.compile(rf"{kind} #\\d+(.*?)(?=\nResource[A-Z]|\Z)", re.S)
    matches = pattern.findall(logs)
    if not matches:
        raise SystemExit(f"missing {kind.lower()} telemetry in collector logs")
    return matches

def ensure_attributes(blocks, kind):
    required = [
        "service.name",
        "service.namespace",
        "service.component",
        "rpp.mode",
        "rpp.config_source",
        "instance.id",
    ]
    for block in blocks:
        if all(attribute in block for attribute in required):
            return
    missing = ", ".join(required)
    raise SystemExit(f"{kind} missing required resource attributes: {missing}")

span_blocks = extract_blocks("ResourceSpans")
metric_blocks = extract_blocks("ResourceMetrics")

ensure_attributes(span_blocks, "span resources")
ensure_attributes(metric_blocks, "metric resources")
PY

echo "OTLP export smoke test completed successfully" >&2
