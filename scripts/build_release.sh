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
  RPP_RELEASE_BASE_FEATURES  Comma-delimited feature set that is always enabled (default: prod,prover-stwo)
  RPP_RELEASE_FEATURES       Additional feature flags passed to cargo (legacy string form)
  RPP_RELEASE_ARGS           Additional cargo args passed verbatim (supports arrays)
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

if [[ "${SKIP_SNAPSHOT_INTEGRITY_TEST:-0}" != "1" ]]; then
  echo "Running snapshot integrity regression test (root_corruption)"
  if ! cargo test --locked --test root_corruption; then
    echo "::error::Snapshot integrity regression detected. The root_corruption test must pass before building release artifacts." >&2
    exit 1
  fi
fi

COMMAND=("$BUILD_TOOL" "build" "--locked" "--package" "rpp-node" "--bins" "--profile" "$PROFILE" "--target" "$TARGET")

BASE_FEATURES_RAW="${RPP_RELEASE_BASE_FEATURES:---no-default-features --features prod,prover-stwo}"
BASE_FEATURE_ARGS=()
if [[ "$BASE_FEATURES_RAW" == *$' '* ]] || [[ "$BASE_FEATURES_RAW" == -* ]]; then
  read -r -a BASE_FEATURE_ARGS <<<"$BASE_FEATURES_RAW"
else
  BASE_FEATURE_ARGS=(--no-default-features --features "$BASE_FEATURES_RAW")
fi

ADDITIONAL_ARGS=()
if RPP_RELEASE_ARGS_DECL=$(declare -p RPP_RELEASE_ARGS 2>/dev/null); then
  if [[ "$RPP_RELEASE_ARGS_DECL" == declare\ -a* ]]; then
    # shellcheck disable=SC2034 # referenced via indirect expansion
    eval 'ADDITIONAL_ARGS=("${RPP_RELEASE_ARGS[@]}")'
  else
    read -r -a ADDITIONAL_ARGS <<<"$RPP_RELEASE_ARGS"
  fi
elif [[ -n "${RPP_RELEASE_FEATURES:-}" ]]; then
  read -r -a ADDITIONAL_ARGS <<<"$RPP_RELEASE_FEATURES"
fi

declare -A FORBIDDEN_FEATURE_CANONICAL=(
  ["prover-mock"]="prover-mock"
  ["prover_mock"]="prover-mock"
  ["backend-plonky3"]="backend-plonky3"
  ["backend_plonky3"]="backend-plonky3"
  ["backend-plonky3-gpu"]="backend-plonky3-gpu"
  ["backend_plonky3_gpu"]="backend-plonky3-gpu"
)

declare -A FORBIDDEN_FEATURE_MESSAGES=(
  ["prover-mock"]="error: prover-mock feature is not allowed for release builds"
  ["backend-plonky3"]="error: backend-plonky3 is experimental and cannot be enabled for release builds"
  ["backend-plonky3-gpu"]="error: backend-plonky3-gpu is experimental and cannot be enabled for release builds"
)

report_forbidden_feature() {
  local alias="$1"
  local canonical="${FORBIDDEN_FEATURE_CANONICAL[$alias]}"
  local message="${FORBIDDEN_FEATURE_MESSAGES[$canonical]}"
  if [[ -n "$canonical" && -n "$message" ]]; then
    echo "$message (requested via '$alias')" >&2
  else
    echo "error: forbidden feature '$alias' detected in release build" >&2
  fi
  exit 1
}

check_value_forbidden_feature() {
  local value="$1"
  local alias
  for alias in "${!FORBIDDEN_FEATURE_CANONICAL[@]}"; do
    if [[ "$value" == *"$alias"* ]]; then
      report_forbidden_feature "$alias"
    fi
  done
}

check_forbidden_features() {
  local -n _args=$1
  local i
  for ((i = 0; i < ${#_args[@]}; i++)); do
    local arg="${_args[i]}"
    case "$arg" in
      --features|-F)
        if (( i + 1 < ${#_args[@]} )); then
          check_value_forbidden_feature "${_args[i+1]}"
        fi
        ((i++))
        ;;
      --features=*)
        check_value_forbidden_feature "${arg#*=}"
        ;;
      -F*)
        check_value_forbidden_feature "${arg#-F}"
        ;;
      *)
        check_value_forbidden_feature "$arg"
        ;;
    esac
  done
}

check_forbidden_features BASE_FEATURE_ARGS
check_forbidden_features ADDITIONAL_ARGS

COMMAND+=("${BASE_FEATURE_ARGS[@]}")
if [[ ${#ADDITIONAL_ARGS[@]} -gt 0 ]]; then
  COMMAND+=("${ADDITIONAL_ARGS[@]}")
fi

echo "Running ${COMMAND[*]}"
"${COMMAND[@]}"

PROFILE_DIR="$PROFILE"
[[ "$PROFILE_DIR" == "release" ]] || PROFILE_DIR="$PROFILE"

TARGET_DIR="target/$TARGET/$PROFILE_DIR"
if [[ ! -d "$TARGET_DIR" ]]; then
  echo "error: build output not found at $TARGET_DIR" >&2
  exit 1
fi

echo "Verifying release feature set for target $TARGET (profile $PROFILE_DIR)"
"$(dirname "$0")/verify_release_features.sh" --target "$TARGET" --profile "$PROFILE_DIR"

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

HASH_OUTPUT="$OUT_DIR/$TARGET/plonky3-setup-hashes.json"
echo "Verifying Plonky3 setup artifacts and emitting hash manifest at $HASH_OUTPUT"
python3 "$(dirname "$0")/generate_plonky3_artifacts.py" \
  "config/plonky3/setup" \
  --verify \
  --hash-output "$HASH_OUTPUT"

if [[ $GENERATE_SBOM -eq 1 ]]; then
  if ! command -v cargo-cyclonedx >/dev/null 2>&1; then
    echo "warning: cargo-cyclonedx not installed, skipping SBOM generation" >&2
  else
    SBOM_PATH="$OUT_DIR/$TARGET/sbom-rpp-node-${TARGET}.json"
    cargo cyclonedx --package rpp-node --format json --output "$SBOM_PATH"
    echo "Generated SBOM at $SBOM_PATH"
  fi
fi

SNAPSHOT_SUMMARY_SCRIPT="$(dirname "$0")/generate_snapshot_summary.py"
if [[ -f "$SNAPSHOT_SUMMARY_SCRIPT" ]]; then
  SUMMARY_PATH="$OUT_DIR/$TARGET/snapshot-manifest-summary-${TARGET}.json"
  echo "Scanning $OUT_DIR/$TARGET for pruning snapshot manifests"
  if python3 "$SNAPSHOT_SUMMARY_SCRIPT" "$OUT_DIR/$TARGET" --output "$SUMMARY_PATH" --target "$TARGET"; then
    if [[ -f "$SUMMARY_PATH" ]]; then
      echo "Snapshot manifest summary written to $SUMMARY_PATH"
    else
      echo "No pruning snapshots detected under $OUT_DIR/$TARGET; summary skipped"
    fi
  else
    echo "error: failed to generate snapshot manifest summary" >&2
    exit 1
  fi
fi

generate_snapshot_verifier_report() {
  local artifacts_dir="$OUT_DIR/$TARGET"
  mapfile -t manifests < <(find "$artifacts_dir" -path '*/manifest/chunks.json' -type f -print | sort)
  if [[ ${#manifests[@]} -eq 0 ]]; then
    echo "error: no pruning snapshot manifests found under $artifacts_dir; snapshot verifier report is required" >&2
    exit 1
  fi
  if [[ -z "${SNAPSHOT_MANIFEST_PUBKEY_HEX:-}" ]]; then
    echo "error: SNAPSHOT_MANIFEST_PUBKEY_HEX must be set to generate the snapshot verifier report" >&2
    exit 1
  fi

  local key_path
  key_path="$(mktemp)"
  printf '%s' "$SNAPSHOT_MANIFEST_PUBKEY_HEX" >"$key_path"

  local specs=()
  local status=0
  local manifest
  for manifest in "${manifests[@]}"; do
    local signature="${manifest}.sig"
    if [[ ! -f "$signature" ]]; then
      echo "error: snapshot manifest signature missing for $manifest" >&2
      status=1
      break
    fi
    local chunk_root
    chunk_root="$(dirname "$(dirname "$manifest")")/chunks"
    if [[ ! -d "$chunk_root" ]]; then
      echo "error: chunk root $chunk_root not found for manifest $manifest" >&2
      status=1
      break
    fi
    local report_path="${manifest%.json}-verify.json"
    if ! cargo run --locked --package snapshot-verify -- \
      --manifest "$manifest" \
      --signature "$signature" \
      --public-key "$key_path" \
      --chunk-root "$chunk_root" \
      --output "$report_path"; then
      status=$?
      break
    fi
    local manifest_rel="${manifest#$artifacts_dir/}"
    local report_rel="${report_path#$artifacts_dir/}"
    specs+=("${manifest_rel}:::${report_rel}")
  done

  rm -f "$key_path"
  if [[ $status -ne 0 ]]; then
    echo "error: snapshot verification failed" >&2
    exit "$status"
  fi

  local aggregate_report="$artifacts_dir/snapshot-verify-report.json"
  python3 - "$artifacts_dir" "$aggregate_report" "${specs[@]}" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

base = Path(sys.argv[1])
output = Path(sys.argv[2])

if len(sys.argv) <= 3:
    print("error: no snapshot verifier reports to aggregate", file=sys.stderr)
    sys.exit(1)

entries = []
all_passed = True

for spec in sys.argv[3:]:
    manifest_rel, report_rel = spec.split(":::", 1)
    report_path = base / report_rel
    try:
        data = json.loads(report_path.read_text())
    except Exception as exc:  # noqa: BLE001
        print(f"error: failed to load snapshot verifier report {report_path}: {exc}", file=sys.stderr)
        sys.exit(1)

    summary = data.get("summary") or {}
    signature = data.get("signature") or {}
    errors = data.get("errors") or []
    failure_counters = [
        summary.get("missing_files", 0),
        summary.get("size_mismatches", 0),
        summary.get("checksum_mismatches", 0),
        summary.get("io_errors", 0),
        summary.get("metadata_incomplete", 0),
    ]
    status = (
        signature.get("signature_valid") is True
        and not errors
        and all(counter == 0 for counter in failure_counters)
    )
    if not status:
        all_passed = False
    entries.append(
        {
            "manifest": manifest_rel,
            "report": report_rel,
            "signature_valid": signature.get("signature_valid"),
            "summary": summary,
            "errors": errors,
            "status": status,
        }
    )

document = {
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "reports": entries,
    "all_passed": all_passed,
}

output.write_text(json.dumps(document, indent=2))

if not all_passed:
    print("snapshot verification reported failures; inspect per-manifest reports", file=sys.stderr)
    sys.exit(1)
PY
  local rc=$?
  if [[ $rc -ne 0 ]]; then
    exit "$rc"
  fi

  sha256sum "$aggregate_report" >"${aggregate_report}.sha256"
  echo "Snapshot verifier report written to $aggregate_report"
}

generate_snapshot_verifier_report
