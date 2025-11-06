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
                            (defaults to default, stwo, and rpp-stark)

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
  plonky3    Force the `backend-plonky3` feature only (experimental matrix)
  prod-stwo-plonky3  Force `prod,prover-stwo,backend-plonky3` with `--no-default-features`
  rpp-stark  Force the `backend-rpp-stark` feature
USAGE
}

PROFILE_ARGS=()
FEATURE_ARGS=()
PASSTHROUGH_ARGS=()
FEATURE_SET_SELECTED=""
SUITES_SELECTED=()
BACKENDS=()
INTEGRATION_FOCUSED_TESTS=(reorg_regressions)

value_requests_plonky3() {
  local value="$1"
  local alias
  for alias in \
    "backend-plonky3" \
    "backend_plonky3" \
    "backend-plonky3-gpu" \
    "backend_plonky3_gpu"; do
    if [[ "$value" == *"$alias"* ]]; then
      return 0
    fi
  done
  return 1
}

args_request_plonky3() {
  local -n _args=$1
  local i
  for ((i = 0; i < ${#_args[@]}; i++)); do
    local arg="${_args[i]}"
    case "$arg" in
      --features|-F)
        if (( i + 1 < ${#_args[@]} )); then
          if value_requests_plonky3 "${_args[i+1]}"; then
            return 0
          fi
        fi
        ((i++))
        ;;
      --features=*)
        if value_requests_plonky3 "${arg#--features=}"; then
          return 0
        fi
        ;;
      -F*)
        if value_requests_plonky3 "${arg#-F}"; then
          return 0
        fi
        ;;
      --all-features)
        return 0
        ;;
      *)
        if value_requests_plonky3 "$arg"; then
          return 0
        fi
        ;;
    esac
  done
  return 1
}

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
        default|stwo|plonky3|prod-stwo-plonky3|rpp-stark)
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
  BACKENDS=(default stwo plonky3 rpp-stark)
fi

plonky3_features_requested=0
if args_request_plonky3 FEATURE_ARGS || args_request_plonky3 PASSTHROUGH_ARGS; then
  plonky3_features_requested=1
fi

if (( plonky3_features_requested )); then
  for backend in "${BACKENDS[@]}"; do
    if [[ "$backend" != "plonky3" && "$backend" != "prod-stwo-plonky3" ]]; then
      echo "error: backend-plonky3 features are experimental and only supported via '--backend plonky3'." >&2
      if [[ "$FEATURE_SET_SELECTED" == "full" ]]; then
        echo "note: '--feature-set full' implicitly enables backend-plonky3. Re-run with '--backend plonky3 --feature-set full' or drop the full feature set." >&2
      else
        echo "note: remove backend-plonky3 from manual --features arguments or restrict '--backend' to 'plonky3' before retrying." >&2
      fi
      echo "Backout: run 'scripts/test.sh --backend plonky3' for the experimental matrix or rerun without backend-plonky3 features." >&2
      exit 1
    fi
  done
fi

run_suite() {
  local suite="$1"
  local backend="$2"
  local -a backend_args=()
  local -a toolchain=()

  case "$backend" in
    default)
      backend_args=()
      toolchain=()
      ;;
    stwo)
      backend_args=("--no-default-features" "--features" "stwo")
      toolchain=("+nightly-2025-07-14")
      ;;
    plonky3)
      backend_args=("--features" "backend-plonky3")
      ;;
    prod-stwo-plonky3)
      backend_args=("--no-default-features" "--features" "prod,prover-stwo,backend-plonky3")
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

  local -a command=(cargo "${toolchain[@]}" test "${PROFILE_ARGS[@]}" "${backend_args[@]}" "${PASSTHROUGH_ARGS[@]}")

  case "$suite" in
    unit)
      command+=(--lib --bins)
      ;;
    integration)
      command+=(--tests --features integration)
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

run_integration_focus_tests() {
  local backend="$1"
  if [[ ${#INTEGRATION_FOCUSED_TESTS[@]} -eq 0 ]]; then
    return 0
  fi

  local -a backend_args=()
  local -a toolchain=()
  case "$backend" in
    default)
      backend_args=()
      toolchain=()
      ;;
    stwo)
      backend_args=("--no-default-features" "--features" "stwo")
      toolchain=("+nightly-2025-07-14")
      ;;
    plonky3)
      backend_args=("--features" "backend-plonky3")
      ;;
    prod-stwo-plonky3)
      backend_args=("--no-default-features" "--features" "prod,prover-stwo,backend-plonky3")
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

  for test_name in "${INTEGRATION_FOCUSED_TESTS[@]}"; do
    local -a command=(
      cargo "${toolchain[@]}" test
      "${PROFILE_ARGS[@]}"
      "${backend_args[@]}"
      "${PASSTHROUGH_ARGS[@]}"
      --features
      integration
      --test
      "$test_name"
    )
    echo "==> Running integration test $test_name (${backend})"
    "${command[@]}"
  done
}

prepare_backend() {
  local backend="$1"
  case "$backend" in
    plonky3|prod-stwo-plonky3)
      echo "==> Verifying Plonky3 setup artifacts (${backend})"
      cargo xtask plonky3-verify
      ;;
  esac
}

declare -A PREPARED_BACKENDS=()
for backend in "${BACKENDS[@]}"; do
  if [[ -z "${PREPARED_BACKENDS[$backend]:-}" ]]; then
    prepare_backend "$backend"
    PREPARED_BACKENDS[$backend]=1
  fi
  for suite in "${SUITES_SELECTED[@]}"; do
    run_suite "$suite" "$backend"
    if [[ "$suite" == "integration" ]]; then
      run_integration_focus_tests "$backend"
    fi
  done
done
