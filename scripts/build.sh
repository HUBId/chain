#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

wallet_toolchain_channel() {
  local file="${REPO_ROOT}/rust-toolchain.wallet.toml"
  if [[ ! -f "${file}" ]]; then
    return 1
  fi
  python3 - <<'PY' "${file}"
import sys
import tomllib

path = sys.argv[1]
data = tomllib.loads(open(path, "rb").read())
toolchain = data.get("toolchain", {})
channel = toolchain.get("channel")
if not channel:
    raise SystemExit(1)
print(channel)
PY
}

append_rustflag() {
  local flag="$1"
  if [[ -z "${RUSTFLAGS:-}" ]]; then
    export RUSTFLAGS="${flag}"
    return
  fi
  if [[ " ${RUSTFLAGS} " != *" ${flag} "* ]]; then
    export RUSTFLAGS="${RUSTFLAGS} ${flag}"
  fi
}

ensure_source_date_epoch() {
  if [[ -n "${SOURCE_DATE_EPOCH:-}" ]]; then
    return
  fi
  SOURCE_DATE_EPOCH="$(git -C "${REPO_ROOT}" log -1 --format=%ct)"
  export SOURCE_DATE_EPOCH
}

if [[ -z "${RUSTFLAGS:-}" ]]; then
  export RUSTFLAGS="-D warnings"
elif [[ " ${RUSTFLAGS} " != *" -D warnings "* ]]; then
  export RUSTFLAGS="${RUSTFLAGS} -D warnings"
fi

: "${CARGO_TERM_COLOR:=always}"
export CARGO_TERM_COLOR

usage() {
  cat <<'USAGE'
Usage: scripts/build.sh [options] [-- <cargo build args>]

A thin wrapper around `cargo build` that standardises common build
profiles and feature combinations used in the project.

Options:
  --release                 Build artifacts in release mode (alias for --profile release)
  --profile <name>          Build with the named cargo profile
  --feature-set <name>      Use a predefined feature matrix (default|minimal|full)
  --backend <name>          Build for a specific backend (default|stwo|plonky3|rpp-stark)
  --plonky3-mirror-help     Print instructions for using the local Plonky3 mirror
  --features <features>     Pass a custom feature list to cargo
  --no-default-features     Disable default features
  --all-features            Enable all features
  --target <triple>         Build for a specific target triple
  --package <name>          Build only the specified package
  --bin <name>              Build only the specified binary
  --example <name>          Build only the specified example
  --help                    Show this help message and exit
  --                        Pass the remaining arguments directly to cargo

Feature sets:
  default   Use the workspace default features (current cargo behaviour)
  minimal   Disable default features (`--no-default-features`)
  full      Enable all features (`--all-features`)

Plonky3 mirror:
  The experimental Plonky3 backend can be pointed at the offline mirror under
  `third_party/plonky3/`. Refresh the mirror with `make vendor-plonky3` (or by
  running `python3 scripts/vendor_plonky3/refresh.py` directly) to regenerate
  the crate set and `third_party/plonky3/config.toml`. Apply the generated
  `[patch.crates-io]` entries by exporting `CARGO_CONFIG=$(pwd)/third_party/plonky3/config.toml`
  (or merging the snippet into `cargo/config.toml`) before invoking this
  script. Set `CHAIN_PLONKY3_EXPERIMENTAL=1` when opting into the backend to
  acknowledge the experimental status.
USAGE
}

plonky3_mirror_help() {
  cat <<'HELP'
Plonky3 mirror guidance
=======================

1. Refresh the mirror:
     make vendor-plonky3
   This runs `python3 scripts/vendor_plonky3/refresh.py`, which rewrites the
   crates below `third_party/plonky3/`, emits `config.toml`, and updates the
   checksum manifest. The command honours `PLONKY3_VENDOR_*` environment
   variables for custom locations.
2. Point Cargo at the mirror:
     export CARGO_CONFIG="$(pwd)/third_party/plonky3/config.toml"
   Alternatively, merge the generated snippet into `cargo/config.toml` to
   enable the `[patch.crates-io]` entries repository-wide.
3. Acknowledge the experimental backend before building:
     export CHAIN_PLONKY3_EXPERIMENTAL=1

After these steps, run `scripts/build.sh --backend plonky3` (optionally with
additional feature flags) to build against the mirrored crates.
HELP
}

PROFILE_ARGS=()
FEATURE_ARGS=()
PASSTHROUGH_ARGS=()
FEATURE_SET_SELECTED=""
BACKEND="default"
TOOLCHAIN_ARGS=()
SELECTED_PACKAGES=()
SELECTED_BINS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --release)
      if [[ ${#PROFILE_ARGS[@]} -ne 0 ]]; then
        echo "error: --release/--profile specified multiple times" >&2
        exit 1
      fi
      PROFILE_ARGS=("--release")
      shift
      ;;
    --profile)
      if [[ ${#PROFILE_ARGS[@]} -ne 0 ]]; then
        echo "error: --profile specified multiple times" >&2
        exit 1
      fi
      if [[ $# -lt 2 ]]; then
        echo "error: --profile requires a value" >&2
        exit 1
      fi
      PROFILE_ARGS=("--profile" "$2")
      shift 2
      ;;
    --feature-set)
      if [[ $# -lt 2 ]]; then
        echo "error: --feature-set requires a value" >&2
        exit 1
      fi
      if [[ -n "$FEATURE_SET_SELECTED" ]]; then
        echo "error: feature set already specified" >&2
        exit 1
      fi
      case "$2" in
        default)
          FEATURE_ARGS=()
          FEATURE_SET_SELECTED="default"
          ;;
        minimal)
          FEATURE_ARGS=("--no-default-features")
          FEATURE_SET_SELECTED="minimal"
          ;;
        full)
          FEATURE_ARGS=("--all-features")
          FEATURE_SET_SELECTED="full"
          ;;
        *)
          echo "error: unknown feature set '$2'" >&2
          exit 1
          ;;
      esac
      shift 2
      ;;
    --features)
      if [[ $# -lt 2 ]]; then
        echo "error: --features requires a value" >&2
        exit 1
      fi
      FEATURE_ARGS+=("--features" "$2")
      shift 2
      ;;
    --no-default-features|--all-features)
      FEATURE_ARGS+=("$1")
      shift
      ;;
    --plonky3-mirror-help)
      plonky3_mirror_help
      exit 0
      ;;
    --backend)
      if [[ $# -lt 2 ]]; then
        echo "error: --backend requires a value" >&2
        exit 1
      fi
      case "$2" in
        default|stwo|plonky3|rpp-stark)
          BACKEND="$2"
          ;;
        *)
          echo "error: unknown backend '$2'" >&2
          exit 1
          ;;
      esac
      shift 2
      ;;
    --target|--package|--bin|--example)
      if [[ $# -lt 2 ]]; then
        echo "error: $1 requires a value" >&2
        exit 1
      fi
      PASSTHROUGH_ARGS+=("$1" "$2")
      if [[ "$1" == "--package" ]]; then
        SELECTED_PACKAGES+=("$2")
      elif [[ "$1" == "--bin" ]]; then
        SELECTED_BINS+=("$2")
      fi
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    --)
      shift
      PASSTHROUGH_ARGS+=("$@")
      break
      ;;
    *)
      PASSTHROUGH_ARGS+=("$1")
      shift
      ;;
  esac
done

case "$BACKEND" in
  default)
    BACKEND_ARGS=()
    TOOLCHAIN_ARGS=()
    ;;
  stwo)
    BACKEND_ARGS=("--no-default-features" "--features" "stwo")
    TOOLCHAIN_ARGS=("+nightly-2025-07-14")
    ;;
  plonky3)
    BACKEND_ARGS=("--features" "backend-plonky3")
    TOOLCHAIN_ARGS=()
    ;;
  rpp-stark)
    BACKEND_ARGS=("--features" "backend-rpp-stark")
    TOOLCHAIN_ARGS=()
    ;;
  *)
    echo "error: unsupported backend '$BACKEND'" >&2
    exit 1
    ;;
esac

WALLET_TARGETED=0
if [[ ${#SELECTED_PACKAGES[@]} -gt 0 || ${#SELECTED_BINS[@]} -gt 0 ]]; then
  for pkg in "${SELECTED_PACKAGES[@]}"; do
    case "${pkg}" in
      rpp-wallet|rpp-wallet-lib|rpp-wallet-interface|wallet-integration-tests)
        WALLET_TARGETED=1
        break
        ;;
    esac
  done
  if [[ ${WALLET_TARGETED} -eq 0 ]]; then
    for bin in "${SELECTED_BINS[@]}"; do
      case "${bin}" in
        rpp-wallet|rpp-wallet-gui)
          WALLET_TARGETED=1
          break
          ;;
      esac
    done
  fi
fi

if [[ ${WALLET_TARGETED} -eq 1 && ${#TOOLCHAIN_ARGS[@]} -eq 0 ]]; then
  if channel="$(wallet_toolchain_channel 2>/dev/null)"; then
    TOOLCHAIN_ARGS=("+${channel}")
  fi
fi

if [[ "${REPRO_MODE:-0}" == "1" ]]; then
  ensure_source_date_epoch
  append_rustflag "--remap-path-prefix=${REPO_ROOT}=/repro/workspace"
  if [[ ${#PROFILE_ARGS[@]} -eq 0 ]]; then
    PROFILE_ARGS=("--profile" "repro")
  fi
fi

cargo "${TOOLCHAIN_ARGS[@]}" build "${PROFILE_ARGS[@]}" "${BACKEND_ARGS[@]}" "${FEATURE_ARGS[@]}" "${PASSTHROUGH_ARGS[@]}"
