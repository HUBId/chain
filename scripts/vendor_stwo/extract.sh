#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DEFAULT_ARCHIVE="${REPO_ROOT}/vendor/stwo-dev/stwo-dev.zip"
DEFAULT_STAGING="${REPO_ROOT}/vendor/stwo-dev/0.1.1/staging"

usage() {
  cat <<USAGE
Usage: ${0##*/} [--archive PATH] [--staging DIR]

Extract the upstream stwo-dev.zip archive into a staging directory that can
be inspected before the segmented import.

Options:
  --archive PATH   Path to the stwo-dev.zip archive. Defaults to
                   ${DEFAULT_ARCHIVE}.
  --staging DIR    Directory to extract the archive into. Defaults to
                   ${DEFAULT_STAGING}.
  -h, --help       Show this help text.
USAGE
}

archive_path="${DEFAULT_ARCHIVE}"
staging_dir="${DEFAULT_STAGING}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --archive)
      archive_path="$2"
      shift 2
      ;;
    --staging)
      staging_dir="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ ! -f "${archive_path}" ]]; then
  echo "Archive not found: ${archive_path}" >&2
  exit 1
fi

mkdir -p "${staging_dir}"
rm -rf "${staging_dir}"/*

echo "Extracting ${archive_path} -> ${staging_dir}" >&2
unzip -q "${archive_path}" -d "${staging_dir}"

echo "Extraction finished." >&2
