#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || echo "")
if [ -z "$REPO_ROOT" ]; then
  echo "error: could not determine repo root" >&2
  exit 1
fi

LOG_PATH="$REPO_ROOT/logs/rpp_golden_vector_checksums.log"
BASELINE="$REPO_ROOT/tests/baselines/rpp_golden_vector_checksums.log"

if [ ! -f "$LOG_PATH" ]; then
  cat >&2 <<'ERR'
error: logs/rpp_golden_vector_checksums.log is missing
hint: run the backend-rpp-stark golden vector tests first so the metadata section is populated, for example:
  cargo test --locked --features backend-rpp-stark --test interop_rpp_stark
ERR
  exit 1
fi

if [ ! -d "$(dirname "$BASELINE")" ]; then
  mkdir -p "$(dirname "$BASELINE")"
fi

cp "$LOG_PATH" "$BASELINE"

echo "updated baseline at $BASELINE"

git diff --stat -- "$BASELINE"
git diff -- "$BASELINE"
