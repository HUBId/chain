#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/checksums.sh --output <file> <artifact> [<artifact>...]

Generate a SHA256 manifest covering the provided artifacts.
USAGE
}

OUTPUT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)
      [[ $# -lt 2 ]] && { echo "error: --output requires a value" >&2; exit 1; }
      OUTPUT="$2"
      shift 2
      ;;
    --help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    -*)
      echo "error: unknown option '$1'" >&2
      usage >&2
      exit 1
      ;;
    *)
      break
      ;;
  esac
done

if [[ -z "$OUTPUT" ]]; then
  echo "error: --output is required" >&2
  usage >&2
  exit 1
fi

if [[ $# -eq 0 ]]; then
  echo "error: no artifacts supplied" >&2
  usage >&2
  exit 1
fi

mkdir -p "$(dirname "$OUTPUT")"

HASH_CMD=()
if command -v sha256sum >/dev/null 2>&1; then
  HASH_CMD=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
  HASH_CMD=(shasum -a 256)
else
  echo "error: neither sha256sum nor shasum is available" >&2
  exit 1
fi

{
  for artifact in "$@"; do
    if [[ ! -f "$artifact" ]]; then
      echo "error: artifact '$artifact' not found" >&2
      exit 1
    fi
    "${HASH_CMD[@]}" "$artifact"
  done
} | sort >"$OUTPUT"

echo "Wrote checksum manifest to $OUTPUT"
