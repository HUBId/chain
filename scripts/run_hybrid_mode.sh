#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=lib/rpp-node-mode-common.sh
. "${SCRIPT_DIR}/lib/rpp-node-mode-common.sh"

MODE="hybrid"
NODE_CONFIG_PATH="${RPP_HYBRID_NODE_CONFIG_PATH:-${RPP_NODE_CONFIG_PATH:-${REPO_ROOT}/config/hybrid.toml}}"
WALLET_CONFIG_PATH="${RPP_HYBRID_WALLET_CONFIG_PATH:-${RPP_WALLET_CONFIG_PATH:-${REPO_ROOT}/config/wallet.toml}}"

if [[ ! -f "${NODE_CONFIG_PATH}" ]]; then
  echo "error: default hybrid node config not found at ${NODE_CONFIG_PATH}" >&2
  exit 1
fi
if [[ ! -f "${WALLET_CONFIG_PATH}" ]]; then
  echo "error: default wallet config not found at ${WALLET_CONFIG_PATH}" >&2
  exit 1
fi

BIN="${RPP_NODE_BIN:-rpp-node}"
HEALTH_TIMEOUT="${RPP_HYBRID_HEALTH_TIMEOUT:-${RPP_NODE_HEALTH_TIMEOUT:-120}}"

if [[ -n "${RPP_HYBRID_HEALTH_URLS:-}" ]]; then
  read -r -a HEALTH_ENDPOINTS <<< "${RPP_HYBRID_HEALTH_URLS}"
else
  HEALTH_ENDPOINTS=(
    "http://127.0.0.1:7070/health/live"
    "http://127.0.0.1:7070/health/ready"
  )
fi

rpp_assert_command "curl"
rpp_assert_command "${BIN}"

CMD_ARGS=("$@")
if ! rpp_has_flag "--config" "${CMD_ARGS[@]}"; then
  CMD_ARGS=("--config" "${NODE_CONFIG_PATH}" "${CMD_ARGS[@]}")
fi
if ! rpp_has_flag "--wallet-config" "${CMD_ARGS[@]}"; then
  CMD_ARGS+=("--wallet-config" "${WALLET_CONFIG_PATH}")
fi

if [[ -n "${RPP_NODE_DATA_DIR:-}" ]] && ! rpp_has_flag "--data-dir" "${CMD_ARGS[@]}"; then
  CMD_ARGS+=("--data-dir" "${RPP_NODE_DATA_DIR}")
fi

LOG_LEVEL="${RPP_HYBRID_LOG_LEVEL:-${RPP_NODE_LOG_LEVEL:-}}"
if [[ -n "${LOG_LEVEL}" ]] && ! rpp_has_flag "--log-level" "${CMD_ARGS[@]}"; then
  CMD_ARGS+=("--log-level" "${LOG_LEVEL}")
fi

echo "launching ${MODE} runtime via ${BIN}" >&2
"${BIN}" hybrid "${CMD_ARGS[@]}" &
RPP_NODE_CHILD_PID=$!

trap 'rpp_handle_signal INT' INT
trap 'rpp_handle_signal TERM' TERM

rpp_check_endpoints "${RPP_NODE_CHILD_PID}" "${HEALTH_TIMEOUT}" "${HEALTH_ENDPOINTS[@]}"

echo "runtime ready (mode=${MODE}, pid=${RPP_NODE_CHILD_PID})"

trap - INT TERM
wait "${RPP_NODE_CHILD_PID}"
exit $?
