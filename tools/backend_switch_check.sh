#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Validate that a running node is routing proofs to the expected backend.

Usage: tools/backend_switch_check.sh --url <http://host:port> --backend <name> [--interval <seconds>] [--attempts <count>]

Options:
  --url         Base URL of the node's RPC endpoint (e.g. http://127.0.0.1:8080)
  --backend     Backend name to validate (e.g. stwo, plonky3, rpp-stark)
  --interval    Seconds to wait between polls (default: 2)
  --attempts    Number of polls to perform before failing (default: 10)
  --help        Show this message

The check succeeds once the verifier metrics for the chosen backend increase
(accepted + rejected + bypassed) compared to the initial sample.
USAGE
}

require() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: missing dependency: $1" >&2
    exit 1
  fi
}

URL=""
BACKEND=""
INTERVAL=2
ATTEMPTS=10

while [[ $# -gt 0 ]]; do
  case "$1" in
    --url)
      URL=${2:-}
      shift 2
      ;;
    --backend)
      BACKEND=${2:-}
      shift 2
      ;;
    --interval)
      INTERVAL=${2:-}
      shift 2
      ;;
    --attempts)
      ATTEMPTS=${2:-}
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown option $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$URL" || -z "$BACKEND" ]]; then
  echo "error: --url and --backend are required" >&2
  usage
  exit 1
fi

require curl
require jq

status_url="${URL%/}/status/node"
echo "Sampling verifier metrics from ${status_url} for backend '${BACKEND}'"

backend_total() {
  curl -fsSL --max-time 5 "$status_url" \
    | jq -r --arg backend "$BACKEND" '(.backend_health[$backend].verifier // null) | if . == null then "" else (.accepted + .rejected + .bypassed) end'
}

baseline=$(backend_total)
if [[ -z "$baseline" ]]; then
  echo "error: backend '$BACKEND' not present in backend_health report" >&2
  exit 1
fi

echo "Baseline total: $baseline"

for (( attempt=1; attempt<=ATTEMPTS; attempt++ )); do
  sleep "$INTERVAL"
  current=$(backend_total)
  if [[ -z "$current" ]]; then
    echo "error: backend '$BACKEND' disappeared from backend_health report" >&2
    exit 1
  fi
  echo "Attempt $attempt/${ATTEMPTS}: current total $current"
  if [[ "$current" -gt "$baseline" ]]; then
    echo "Backend '${BACKEND}' is receiving proofs (total increased from $baseline to $current)."
    exit 0
  fi
done

echo "error: verifier metrics for backend '$BACKEND' did not increase after $ATTEMPTS attempts" >&2
exit 1
