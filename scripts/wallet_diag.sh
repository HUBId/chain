#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: wallet_diag.sh [options]

Options:
  --endpoint URL      Wallet health endpoint to query (default: http://127.0.0.1:9942/health).
  --auth-token TOKEN  Bearer token used to authenticate against the wallet RPC surface.
  --mode MODE         Runtime mode being exercised (for logging only).
  --log PATH          Optional path to the runtime log file to sanity check startup markers.
  -h, --help          Show this message and exit.
USAGE
}

ENDPOINT="http://127.0.0.1:9942/health"
AUTH_TOKEN=""
MODE="wallet"
LOG_PATH=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --endpoint)
      [[ $# -lt 2 ]] && { echo "--endpoint requires a value" >&2; exit 1; }
      ENDPOINT="$2"
      shift 2
      ;;
    --auth-token)
      [[ $# -lt 2 ]] && { echo "--auth-token requires a value" >&2; exit 1; }
      AUTH_TOKEN="$2"
      shift 2
      ;;
    --mode)
      [[ $# -lt 2 ]] && { echo "--mode requires a value" >&2; exit 1; }
      MODE="$2"
      shift 2
      ;;
    --log)
      [[ $# -lt 2 ]] && { echo "--log requires a path" >&2; exit 1; }
      LOG_PATH="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -n "${LOG_PATH}" && -f "${LOG_PATH}" ]]; then
  if ! grep -q "wallet runtime initialised" "${LOG_PATH}"; then
    echo "wallet_diag: runtime logs missing wallet startup marker" >&2
    exit 1
  fi
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "wallet_diag: curl is required" >&2
  exit 1
fi

CMD=(curl -fsS)
if [[ -n "${AUTH_TOKEN}" ]]; then
  CMD+=(-H "Authorization: Bearer ${AUTH_TOKEN}")
fi
CMD+=("${ENDPOINT}")

if ! OUTPUT="$(${CMD[@]} 2>&1)"; then
  echo "wallet_diag: failed to query ${ENDPOINT}" >&2
  echo "${OUTPUT}" >&2
  exit 1
fi

echo "wallet_diag: ${MODE} runtime healthy -> ${OUTPUT}"
