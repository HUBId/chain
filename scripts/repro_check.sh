#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
WORK_ROOT="${REPO_ROOT}/target/repro-check"
mkdir -p "${WORK_ROOT}"

usage() {
  cat <<'USAGE'
Usage: scripts/repro_check.sh [options]

Run the wallet bundle (and optional installer) builders twice in isolated
build directories and compare the resulting artifacts byte-for-byte.

Options:
  --target <triple>   Target triple to pass to the builders.
                      Defaults to the host triple reported by `rustc -Vv`.
  --version <tag>     Version string embedded into the artifacts.
                      Defaults to `git describe --tags --dirty --always`.
  --bundle-arg <arg>  Extra argument forwarded to each `wallet-bundle`
                      invocation. Repeatable.
  --installer-arg <arg>
                      Extra argument forwarded to each `wallet-installer`
                      invocation (if available). Repeatable.
  -h, --help          Show this help text.
USAGE
}

TARGET=""
VERSION=""
BUNDLE_ARGS=()
INSTALLER_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      TARGET="$2"
      shift 2
      ;;
    --version)
      VERSION="$2"
      shift 2
      ;;
    --bundle-arg)
      BUNDLE_ARGS+=("$2")
      shift 2
      ;;
    --installer-arg)
      INSTALLER_ARGS+=("$2")
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument '$1'" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "${TARGET}" ]]; then
  TARGET="$(rustc -Vv | awk '/^host: / { print $2 }')"
fi
if [[ -z "${VERSION}" ]]; then
  VERSION="$(git -C "${REPO_ROOT}" describe --tags --dirty --always)"
fi
BUNDLE_NAME="wallet-bundle-${VERSION}-${TARGET}"

ensure_source_date_epoch() {
  if [[ -n "${SOURCE_DATE_EPOCH:-}" ]]; then
    return
  fi
  SOURCE_DATE_EPOCH="$(git -C "${REPO_ROOT}" log -1 --format=%ct)"
  export SOURCE_DATE_EPOCH
}

builder_available() {
  local subcommand="$1"
  if cargo xtask "${subcommand}" --help >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

run_build() {
  local label="$1"
  local run_dir="${WORK_ROOT}/${label}"
  rm -rf "${run_dir}"
  mkdir -p "${run_dir}"
  local dist_dir="${run_dir}/dist"
  mkdir -p "${dist_dir}"
  local target_dir="${run_dir}/target"
  echo "repro_check: building run ${label}"
  (
    cd "${REPO_ROOT}"
    export REPRO_MODE=1
    ensure_source_date_epoch
    export SOURCE_DATE_EPOCH
    export CARGO_TARGET_DIR="${target_dir}"
    cargo xtask wallet-bundle \
      --target "${TARGET}" \
      --version "${VERSION}" \
      --output "${dist_dir}" \
      "${BUNDLE_ARGS[@]}"
    if builder_available wallet-installer; then
      cargo xtask wallet-installer \
        --target "${TARGET}" \
        --version "${VERSION}" \
        --output "${dist_dir}" \
        "${INSTALLER_ARGS[@]}"
    else
      echo "repro_check: wallet-installer not found, skipping" >&2
    fi
  )
}

compare_trees() {
  local left="$1"
  local right="$2"
  if ! diff -rq --no-dereference "${left}" "${right}" >/tmp/repro_diff.$$; then
    cat /tmp/repro_diff.$$ >&2
    rm -f /tmp/repro_diff.$$
    echo "repro_check: artifact mismatch detected" >&2
    return 1
  fi
  rm -f /tmp/repro_diff.$$
}

run_build run1
run_build run2

compare_trees "${WORK_ROOT}/run1/dist" "${WORK_ROOT}/run2/dist"

bundle_path="${WORK_ROOT}/run1/dist/wallet/${TARGET}/${BUNDLE_NAME}.tar.gz"
if [[ -f "${bundle_path}" ]]; then
  echo "repro_check: reproduced bundle ${bundle_path}"
else
  echo "repro_check: warning - bundle ${bundle_path} missing" >&2
fi

echo "repro_check: reproducibility check completed"
