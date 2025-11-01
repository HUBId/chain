#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=lib/rpp-node-mode-common.sh
. "${SCRIPT_DIR}/lib/rpp-node-mode-common.sh"

MODE="wallet"
DEFAULT_CONFIG_PATH="${RPP_WALLET_CONFIG_PATH:-${REPO_ROOT}/config/wallet.toml}"

# Optional environment variables:
#   RPP_WALLET_RPC_AUTH_TOKEN - when set, send `Authorization: Bearer <token>`
#     with every readiness probe (overrides `RPP_NODE_RPC_AUTH_TOKEN`).
#   RPP_WALLET_HEALTH_HEADERS - newline-separated list of additional headers to
#     attach to readiness probes (e.g. `X-Api-Key: example`).

if [[ ! -f "${DEFAULT_CONFIG_PATH}" ]]; then
  echo "error: default wallet config not found at ${DEFAULT_CONFIG_PATH}" >&2
  exit 1
fi

BIN="${RPP_NODE_BIN:-rpp-node}"
HEALTH_TIMEOUT="${RPP_WALLET_HEALTH_TIMEOUT:-${RPP_NODE_HEALTH_TIMEOUT:-120}}"

if [[ -n "${RPP_WALLET_HEALTH_URLS:-}" ]]; then
  read -r -a HEALTH_ENDPOINTS <<< "${RPP_WALLET_HEALTH_URLS}"
else
  HEALTH_ENDPOINTS=(
    "http://127.0.0.1:9090/health/live"
    "http://127.0.0.1:9090/health/ready"
  )
fi

rpp_assert_command "curl"
rpp_assert_command "${BIN}"

CMD_ARGS=("$@")
if ! rpp_has_flag "--config" "${CMD_ARGS[@]}"; then
  CMD_ARGS=("--config" "${DEFAULT_CONFIG_PATH}" "${CMD_ARGS[@]}")
fi

LOG_LEVEL="${RPP_WALLET_LOG_LEVEL:-${RPP_NODE_LOG_LEVEL:-}}"
if [[ -n "${LOG_LEVEL}" ]] && ! rpp_has_flag "--log-level" "${CMD_ARGS[@]}"; then
  CMD_ARGS+=("--log-level" "${LOG_LEVEL}")
fi

echo "launching ${MODE} runtime via ${BIN}" >&2
"${BIN}" wallet "${CMD_ARGS[@]}" &
RPP_NODE_CHILD_PID=$!

trap 'rpp_handle_signal INT' INT
trap 'rpp_handle_signal TERM' TERM

rpp_check_endpoints "${RPP_NODE_CHILD_PID}" "${HEALTH_TIMEOUT}" "${HEALTH_ENDPOINTS[@]}"

echo "runtime ready (mode=${MODE}, pid=${RPP_NODE_CHILD_PID})"

trap - INT TERM
wait "${RPP_NODE_CHILD_PID}"
exit $?
