#!/usr/bin/env bash
set -euo pipefail

# Runs the libp2p simulator smoke tests with the ci-sim feature enabled and
# gathers generated artefacts in a predictable directory for CI to archive.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
ARTIFACT_DIR="${REPO_ROOT}/ci-artifacts/sim-smoke"

rm -rf "${ARTIFACT_DIR}"
mkdir -p "${ARTIFACT_DIR}"

pushd "${REPO_ROOT}" >/dev/null

export RPP_SIM_REQUIRE_DETERMINISTIC="1"

cargo test \
  --manifest-path rpp/sim/Cargo.toml \
  --features ci-sim \
  --test sim_smoke \
  -- \
  --nocapture

popd >/dev/null

# Collect deterministic simulator summaries for CI artefacts.
if [[ -f "${REPO_ROOT}/target/sim-smoke-summary.json" ]]; then
  cp "${REPO_ROOT}/target/sim-smoke-summary.json" "${ARTIFACT_DIR}/"
fi

if [[ -d "${REPO_ROOT}/target/sim-smoke" ]]; then
  mkdir -p "${ARTIFACT_DIR}/target-sim-smoke"
  cp -a "${REPO_ROOT}/target/sim-smoke/." "${ARTIFACT_DIR}/target-sim-smoke/"
fi

echo "Simulation smoke artefacts stored in ${ARTIFACT_DIR}" >&2
