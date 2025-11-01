#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/build_release.sh --target <triple> [options]

Build and package the rpp-node binaries for distribution.

Options:
  --target <triple>        Target triple to compile for (required)
  --profile <name>         Cargo profile to compile with (default: release)
  --out-dir <path>         Directory to place the packaged artifacts (default: dist/artifacts)
  --tool <cargo|cross>     Build tool to invoke (default: cargo)
  --skip-sbom              Do not generate a CycloneDX SBOM
  --help                   Show this help message and exit

Environment variables:
  RPP_RELEASE_FEATURES     Additional feature flags passed to cargo
USAGE
}

TARGET=""
PROFILE="release"
OUT_DIR="dist/artifacts"
BUILD_TOOL="cargo"
GENERATE_SBOM=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      [[ $# -lt 2 ]] && { echo "error: --target requires a value" >&2; exit 1; }
      TARGET="$2"
      shift 2
      ;;
    --profile)
      [[ $# -lt 2 ]] && { echo "error: --profile requires a value" >&2; exit 1; }
      PROFILE="$2"
      shift 2
      ;;
    --out-dir)
      [[ $# -lt 2 ]] && { echo "error: --out-dir requires a value" >&2; exit 1; }
      OUT_DIR="$2"
      shift 2
      ;;
    --tool)
      [[ $# -lt 2 ]] && { echo "error: --tool requires a value" >&2; exit 1; }
      case "$2" in
        cargo|cross)
          BUILD_TOOL="$2"
          ;;
        *)
          echo "error: unknown build tool '$2'" >&2
          exit 1
          ;;
      esac
      shift 2
      ;;
    --skip-sbom)
      GENERATE_SBOM=0
      shift
      ;;
    --help)
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

if [[ -z "$TARGET" ]]; then
  echo "error: --target is required" >&2
  usage >&2
  exit 1
fi

if [[ ! -f Cargo.toml ]]; then
  echo "error: scripts/build_release.sh must be run from the repository root" >&2
  exit 1
fi

COMMAND=("$BUILD_TOOL" "build" "--locked" "--package" "rpp-node" "--bins" "--profile" "$PROFILE" "--target" "$TARGET")

if [[ -n "${RPP_RELEASE_FEATURES:-}" ]]; then
  read -r -a FEATURE_ARGS <<<"$RPP_RELEASE_FEATURES"
else
  FEATURE_ARGS=(--no-default-features --features prod,prover-stwo)
fi

COMMAND+=("${FEATURE_ARGS[@]}")

echo "Running ${COMMAND[*]}"
"${COMMAND[@]}"

PROFILE_DIR="$PROFILE"
[[ "$PROFILE_DIR" == "release" ]] || PROFILE_DIR="$PROFILE"

TARGET_DIR="target/$TARGET/$PROFILE_DIR"
if [[ ! -d "$TARGET_DIR" ]]; then
  echo "error: build output not found at $TARGET_DIR" >&2
  exit 1
fi

BINARIES=("rpp-node" "node" "wallet" "hybrid" "validator")
mkdir -p "$OUT_DIR/$TARGET"

stage_package() {
  local binary="$1"
  local tarball="$2"
  local dest_dir="$3"
  local binary_source
  binary_source="$TARGET_DIR/$binary"

  if [[ ! -f "$binary_source" ]]; then
    echo "error: expected binary '$binary_source' not found" >&2
    exit 1
  fi

  rm -rf "$dest_dir"
  mkdir -p "$dest_dir/bin"

  install -m 0755 "$binary_source" "$dest_dir/bin/$(basename "$binary_source")"
  install -m 0644 LICENSE.md "$dest_dir/"
  install -m 0644 README.md "$dest_dir/" 2>/dev/null || true

  tar -C "$dest_dir" -czf "$tarball" .
  rm -rf "$dest_dir"
}

for binary in "${BINARIES[@]}"; do
  if [[ "$binary" == "rpp-node" ]]; then
    tar_name="rpp-node-${TARGET}.tar.gz"
  else
    tar_name="rpp-node-${binary}-${TARGET}.tar.gz"
  fi
  tar_path="$OUT_DIR/$TARGET/$tar_name"
  stage_dir="$(mktemp -d)"
  stage_package "$binary" "$tar_path" "$stage_dir"
  echo "Packaged $tar_path"
done

if [[ $GENERATE_SBOM -eq 1 ]]; then
  if ! command -v cargo-cyclonedx >/dev/null 2>&1; then
    echo "warning: cargo-cyclonedx not installed, skipping SBOM generation" >&2
  else
    SBOM_PATH="$OUT_DIR/$TARGET/sbom-rpp-node-${TARGET}.json"
    cargo cyclonedx --package rpp-node --format json --output "$SBOM_PATH"
    echo "Generated SBOM at $SBOM_PATH"
  fi
fi
