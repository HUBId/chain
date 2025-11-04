#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/verify_release_features.sh --target <triple> [--profile <name>]

Validate that the built rpp-node artifacts do not enable forbidden prover features.

Options:
  --target <triple>   Target triple associated with the build output (required)
  --profile <name>    Cargo profile used during the build (default: release)
  --help              Show this help message and exit
USAGE
}

TARGET=""
PROFILE="release"

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
  echo "error: scripts/verify_release_features.sh must be run from the repository root" >&2
  exit 1
fi

TARGET_DIR="target/$TARGET/$PROFILE"
if [[ ! -d "$TARGET_DIR" ]]; then
  echo "error: expected build output under $TARGET_DIR" >&2
  exit 1
fi

forbidden_features=(
  "prover-mock"
  "prover_mock"
  "backend-plonky3"
  "backend_plonky3"
  "backend-plonky3-gpu"
  "backend_plonky3_gpu"
)

check_metadata() {
  local target_triple="$1"
  local forbidden_json
  forbidden_json=$(printf '"%s",' "${forbidden_features[@]}")
  forbidden_json="[${forbidden_json%,}]"

  cargo metadata --format-version 1 --locked --no-deps --filter-platform "$target_triple" \
    | python3 - "$forbidden_json" <<'PY'
import json
import sys

metadata = json.load(sys.stdin)
forbidden = set(json.loads(sys.argv[1]))
resolve = metadata.get("resolve", {})
nodes = resolve.get("nodes", [])
violations = []
for node in nodes:
    if not node["id"].startswith("rpp-node "):
        continue
    active = sorted(set(node.get("features", [])) & forbidden)
    if active:
        violations.append((node["id"], active))

if violations:
    for pkg, feats in violations:
        print(
            f"error: forbidden prover features enabled for {pkg}: {', '.join(feats)}",
            file=sys.stderr,
        )
    sys.exit(1)
PY
}

check_fingerprints() {
  local fingerprint_dir="$1"
  local forbidden_json
  forbidden_json=$(printf '"%s",' "${forbidden_features[@]}")
  forbidden_json="[${forbidden_json%,}]"

  python3 - "$fingerprint_dir" "$forbidden_json" <<'PY'
import json
import os
import sys

fingerprint_dir = sys.argv[1]
forbidden = set(json.loads(sys.argv[2]))
if not os.path.isdir(fingerprint_dir):
    # Leave a hint for callers; metadata already passed so this is informational.
    print(f"warning: fingerprint directory missing at {fingerprint_dir}", file=sys.stderr)
    sys.exit(0)

matches = []
for root, _dirs, files in os.walk(fingerprint_dir):
    for name in files:
        path = os.path.join(root, name)
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                data = handle.read()
        except OSError:
            continue
        active = sorted(feature for feature in forbidden if feature in data)
        if active:
            matches.append((path, active))

if matches:
    for path, feats in matches:
        print(
            f"error: forbidden prover features detected in {path}: {', '.join(feats)}",
            file=sys.stderr,
        )
    sys.exit(1)
PY
}

check_metadata "$TARGET"
check_fingerprints "$TARGET_DIR/.fingerprint"

echo "release feature verification passed for $TARGET ($PROFILE)"
