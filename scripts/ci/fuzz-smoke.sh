#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FUZZ_DIR="${REPO_ROOT}/fuzz"
MAX_TIME="${FUZZ_MAX_TOTAL_TIME:-45}"
SEED="${FUZZ_SEED:-0x5A17F00D}"
TARGETS=(transaction_parser network_messages pruning_proof config_loader)

if ! command -v cargo >/dev/null; then
  echo "cargo is required to run fuzz smoke tests" >&2
  exit 1
fi

pushd "${FUZZ_DIR}" >/dev/null
for target in "${TARGETS[@]}"; do
  echo "==> Running fuzz smoke for ${target}"
  mkdir -p "artifacts/${target}"
  dict_path="dictionaries/${target}.dict"
  args=(
    -seed="${SEED}"
    -max_total_time="${MAX_TIME}"
    -timeout=5
    -artifact_prefix="artifacts/${target}-"
  )
  if [[ -f "${dict_path}" ]]; then
    args+=(-dict="${dict_path}")
  fi
  cargo +nightly fuzz run "${target}" "corpus/${target}" -- "${args[@]}"
done
popd >/dev/null
