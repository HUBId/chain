#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${RUSTFLAGS:-}" ]]; then
  export RUSTFLAGS="-D warnings"
elif [[ " ${RUSTFLAGS} " != *" -D warnings "* ]]; then
  export RUSTFLAGS="${RUSTFLAGS} -D warnings"
fi

: "${CARGO_TERM_COLOR:=always}"
export CARGO_TERM_COLOR

usage() {
  cat <<'USAGE'
Usage: scripts/test.sh [options] [-- <cargo test args>]

Run the project's automated test suites with consistent settings.

Test selection:
  --unit                    Run unit tests (`cargo test --lib --bins`)
  --integration             Run integration tests (`cargo test --tests`)
  --doc                     Run documentation tests
  --all                     Run all test suites (default if none selected)
  --backend <name>          Run the suites for a specific backend (default|stwo|plonky3|rpp-stark)

Build options:
  --release                 Test using the release profile
  --profile <name>          Test using the specified cargo profile
  --feature-set <name>      Use a predefined feature matrix (default|minimal|full)
  --features <features>     Pass a custom feature list to cargo
  --no-default-features     Disable default features
  --all-features            Enable all features
  --target <triple>         Run tests for the specified target
  --package <name>          Run tests for only the given package
  --help                    Show this help message and exit
  --                        Pass the remaining arguments directly to cargo

Backends:
  default    Use the workspace default backend configuration
  stwo       Force the `prover-stwo` feature only
  plonky3    Force the `backend-plonky3` feature only
  rpp-stark  Force the `backend-rpp-stark` feature
USAGE
}

PROFILE_ARGS=()
FEATURE_ARGS=()
PASSTHROUGH_ARGS=()
FEATURE_SET_SELECTED=""
SUITES_SELECTED=()
BACKENDS=()

add_suite() {
  local suite="$1"
  for existing in "${SUITES_SELECTED[@]:-}"; do
    [[ "$existing" == "$suite" ]] && return 0
  done
  SUITES_SELECTED+=("$suite")
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --unit)
      add_suite unit
      shift
      ;;
    --integration)
      add_suite integration
      shift
      ;;
    --doc)
      add_suite doc
      shift
      ;;
    --all)
      SUITES_SELECTED=(unit integration doc)
      shift
      ;;
    --backend)
      if [[ $# -lt 2 ]]; then
        echo "error: --backend requires a value" >&2
        exit 1
      fi
      case "$2" in
        default|stwo|plonky3|rpp-stark)
          BACKENDS+=("$2")
          ;;
        *)
          echo "error: unknown backend '$2'" >&2
          exit 1
          ;;
      esac
      shift 2
      ;;
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
    --target|--package|--bin|--example|--test|--bench)
      if [[ $# -lt 2 ]]; then
        echo "error: $1 requires a value" >&2
        exit 1
      fi
      PASSTHROUGH_ARGS+=("$1" "$2")
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

if [[ ${#SUITES_SELECTED[@]} -eq 0 ]]; then
  SUITES_SELECTED=(unit integration)
fi

if [[ ${#BACKENDS[@]} -eq 0 ]]; then
  BACKENDS=(default rpp-stark)
fi

run_suite() {
  local suite="$1"
  local backend="$2"
  local -a backend_args=()

  case "$backend" in
    default)
      backend_args=()
      ;;
    stwo)
      backend_args=("--no-default-features" "--features" "prover-stwo")
      ;;
    plonky3)
      backend_args=("--features" "backend-plonky3")
      ;;
    rpp-stark)
      backend_args=("--features" "backend-rpp-stark")
      ;;
    *)
      echo "error: unsupported backend '$backend'" >&2
      exit 1
      ;;
  esac

  backend_args+=("${FEATURE_ARGS[@]}")

  local -a command=(cargo test "${PROFILE_ARGS[@]}" "${backend_args[@]}" "${PASSTHROUGH_ARGS[@]}")

  case "$suite" in
    unit)
      command+=(--lib --bins)
      ;;
    integration)
      command+=(--tests)
      ;;
    doc)
      command+=(--doc)
      ;;
    *)
      echo "error: unknown suite '$suite'" >&2
      exit 1
      ;;
  esac

  echo "==> Running $suite tests (${backend})"
  "${command[@]}"
}

for backend in "${BACKENDS[@]}"; do
  for suite in "${SUITES_SELECTED[@]}"; do
    run_suite "$suite" "$backend"
  done
done
