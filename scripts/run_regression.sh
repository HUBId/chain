#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ARTIFACT_ROOT=${RPP_REGRESSION_ARTIFACT_DIR:-"$ROOT_DIR/ci-artifacts/regression"}

mkdir -p "$ARTIFACT_ROOT"/logs "$ARTIFACT_ROOT"/metrics "$ARTIFACT_ROOT"/snapshots

export RPP_REGRESSION_ARTIFACT_DIR="$ARTIFACT_ROOT"
export RUST_LOG=${RUST_LOG:-info}
export RUST_BACKTRACE=${RUST_BACKTRACE:-1}

pushd "$ROOT_DIR" > /dev/null

set +e
cargo test --test regression -- --nocapture "$@" | tee "$ARTIFACT_ROOT/logs/regression.log"
status=${PIPESTATUS[0]}
set -e

popd > /dev/null

exit "$status"
