#!/usr/bin/env bash
set -euo pipefail

# Run the Firewood Go fuzz target with an optional Firewood feature set.
#
# Environment variables:
# - FIREWOOD_RS_FEATURES: Cargo feature list for firewood-ffi (e.g. "branch_factor_256" or "ethhash").
# - FIREWOOD_FUZZTIME: Duration or iteration budget forwarded to `go test -fuzztime` (default: 2m).
# - FIREWOOD_CARGO_PROFILE: Cargo profile used to build firewood-ffi (default: release).

FEATURES=${FIREWOOD_RS_FEATURES:-}
FUZZTIME=${FIREWOOD_FUZZTIME:-2m}
PROFILE=${FIREWOOD_CARGO_PROFILE:-release}

if [[ -n "$FEATURES" && "$FEATURES" == *branch_factor_256* && "$FEATURES" == *ethhash* ]]; then
  echo "branch_factor_256 and ethhash cannot be combined" >&2
  exit 1
fi

feature_args=()
if [[ -n "$FEATURES" ]]; then
  feature_args+=(--features "$FEATURES")
fi

cargo build -p firewood-ffi --locked --profile "$PROFILE" "${feature_args[@]}"

pushd ffi/tests/firewood >/dev/null

go test -run FuzzTree -fuzz=FuzzTree -fuzztime="$FUZZTIME"

popd >/dev/null
