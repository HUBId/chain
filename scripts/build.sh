#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/build.sh [options] [-- <cargo build args>]

A thin wrapper around `cargo build` that standardises common build
profiles and feature combinations used in the project.

Options:
  --release                 Build artifacts in release mode (alias for --profile release)
  --profile <name>          Build with the named cargo profile
  --feature-set <name>      Use a predefined feature matrix (default|minimal|full)
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
USAGE
}

PROFILE_ARGS=()
FEATURE_ARGS=()
PASSTHROUGH_ARGS=()
FEATURE_SET_SELECTED=""
CUSTOM_FEATURES=false

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
      if [[ -n "$FEATURE_SET_SELECTED" || $CUSTOM_FEATURES == true ]]; then
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
      CUSTOM_FEATURES=true
      shift 2
      ;;
    --no-default-features|--all-features)
      FEATURE_ARGS+=("$1")
      CUSTOM_FEATURES=true
      shift
      ;;
    --target|--package|--bin|--example)
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

cargo build "${PROFILE_ARGS[@]}" "${FEATURE_ARGS[@]}" "${PASSTHROUGH_ARGS[@]}"
