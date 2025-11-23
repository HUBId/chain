#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || echo "")
if [ -z "$REPO_ROOT" ]; then
  echo "error: could not determine repo root" >&2
  exit 1
fi

BASELINE="$REPO_ROOT/tests/baselines/rpp_golden_vector_checksums.log"
LOG_PATH="$REPO_ROOT/logs/rpp_golden_vector_checksums.log"

if [ ! -f "$BASELINE" ]; then
  echo "error: missing baseline at $BASELINE" >&2
  exit 1
fi

if [ ! -f "$LOG_PATH" ]; then
  cat >&2 <<'ERR'
error: missing checksum log at logs/rpp_golden_vector_checksums.log
hint: run the backend-rpp-stark golden vector tests (e.g. cargo test --features backend-rpp-stark --test interop_rpp_stark) to regenerate the log.
ERR
  exit 1
fi

if ! diff -u "$BASELINE" "$LOG_PATH"; then
  cat >&2 <<'ERR'
error: rpp golden vector checksums differ from baseline
hint: if the vectors legitimately changed, regenerate the baseline via tools/update_rpp_golden_vector_baseline.sh and include the update in your commit.
ERR
  exit 1
fi

printf 'rpp golden vector checksums match baseline\n'
