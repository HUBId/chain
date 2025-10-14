#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(git rev-parse --show-toplevel)
ARTIFACT_DIR="${REPO_ROOT}/logs/firewood-recovery"
REPORT_PATH="${ARTIFACT_DIR}/firewood_recovery_report.json"
LOG_PATH="${ARTIFACT_DIR}/firewood_recovery.log"

mkdir -p "${ARTIFACT_DIR}"

echo "Running Firewood recovery drill scenario"
(
  cd "${REPO_ROOT}" && \
    cargo run -p storage-firewood --bin firewood_recovery -- --report "${REPORT_PATH}"
) |& tee "${LOG_PATH}"

echo "Firewood recovery drill complete"
echo "Report saved to ${REPORT_PATH}"
echo "Log saved to ${LOG_PATH}"
