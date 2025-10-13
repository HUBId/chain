#!/usr/bin/env bash
set -euo pipefail

CRATE_NAME="malachite"
VERSION="0.4.18"
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd)
VENDOR_ROOT="${REPO_ROOT}/vendor/${CRATE_NAME}/${VERSION}"
DEFAULT_ARCHIVE="${VENDOR_ROOT}/${CRATE_NAME}-${VERSION}.crate"
ARCHIVE_PATH="${1:-${DEFAULT_ARCHIVE}}"
SRC_ROOT="${VENDOR_ROOT}/src"
LOG_FILE="${REPO_ROOT}/logs/vendor_malachite_0_4_18.log"
MANIFEST_DIR="${VENDOR_ROOT}/manifest"
FINAL_LIST="${MANIFEST_DIR}/final_file_list.txt"
DOWNLOAD_URL="https://crates.io/api/v1/crates/${CRATE_NAME}/${VERSION}/download"

mkdir -p "${VENDOR_ROOT}" "${MANIFEST_DIR}" "$(dirname "${LOG_FILE}")"
touch "${LOG_FILE}"

log_event() {
  local level="$1"
  shift
  local message="$*"
  local timestamp
  timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  local formatted="[$timestamp] [$level] $message"
  printf '%s\n' "$formatted"
  printf '%s\n' "$formatted" >>"${LOG_FILE}"
}

fatal() {
  log_event "ERROR" "$*"
  exit 1
}

if [[ ! -f "${ARCHIVE_PATH}" ]]; then
  if command -v curl >/dev/null 2>&1; then
    log_event "INFO" "Archive ${ARCHIVE_PATH} not found, downloading from ${DOWNLOAD_URL}"
    tmp_download="${ARCHIVE_PATH}.download"
    if ! curl -fsSL "${DOWNLOAD_URL}" -H 'User-Agent: chain-unpack-script/0.1 (https://github.com/chain)' -o "${tmp_download}"; then
      rm -f "${tmp_download}"
      fatal "Failed to download archive from ${DOWNLOAD_URL}"
    fi
    mv "${tmp_download}" "${ARCHIVE_PATH}"
    log_event "INFO" "Downloaded archive to ${ARCHIVE_PATH}"
  else
    fatal "Archive ${ARCHIVE_PATH} missing and curl unavailable"
  fi
fi

if [[ ! -f "${ARCHIVE_PATH}" ]]; then
  fatal "Archive not found at ${ARCHIVE_PATH}"
fi

workdir=$(mktemp -d)
trap 'rm -rf "${workdir}"' EXIT

log_event "INFO" "Extracting ${ARCHIVE_PATH}"
if ! tar -xzf "${ARCHIVE_PATH}" -C "${workdir}"; then
  fatal "Failed to extract ${ARCHIVE_PATH}"
fi

SOURCE_DIR="${workdir}/${CRATE_NAME}-${VERSION}"
if [[ ! -d "${SOURCE_DIR}" ]]; then
  fatal "Expected directory ${SOURCE_DIR} after extraction"
fi

rm -rf "${SRC_ROOT}"
mkdir -p "${SRC_ROOT}"
rsync -a "${SOURCE_DIR}/" "${SRC_ROOT}/"
log_event "INFO" "Copied sources into ${SRC_ROOT}"

missing_flag=0
if [[ ! -f "${SRC_ROOT}/Cargo.toml" ]]; then
  log_event "WARN" "Missing expected file: Cargo.toml"
  missing_flag=1
fi
if [[ ! -d "${SRC_ROOT}/src" ]]; then
  log_event "WARN" "Missing expected directory: src/"
  missing_flag=1
fi
if ! compgen -G "${SRC_ROOT}/LICENSE*" >/dev/null; then
  log_event "WARN" "Missing expected license file (LICENSE*)"
  missing_flag=1
fi
if ! compgen -G "${SRC_ROOT}/README*" >/dev/null; then
  log_event "WARN" "Missing expected README file"
  missing_flag=1
fi
if (( missing_flag == 0 )); then
  log_event "INFO" "All expected top-level files are present"
fi

removed_paths=()
declare -a removal_candidates=("tests" "benches" "examples" "examples-ext" "fuzz" "docs" "doc" "ci" ".github")
for candidate in "${removal_candidates[@]}"; do
  if [[ -e "${SRC_ROOT}/${candidate}" ]]; then
    rm -rf "${SRC_ROOT:?}/${candidate}"
    removed_paths+=("${candidate}")
    log_event "INFO" "Removed non-build path: ${candidate}"
  fi
done

if (( ${#removed_paths[@]} == 0 )); then
  log_event "INFO" "No non-build paths needed removal"
else
  log_event "INFO" "Removed paths: ${removed_paths[*]}"
fi

log_event "INFO" "Generating file manifest at ${FINAL_LIST}"
(
  cd "${SRC_ROOT}"
  find . -type f | sort
) >"${FINAL_LIST}"
log_event "INFO" "Wrote $(wc -l <"${FINAL_LIST}") entries to manifest"

log_event "INFO" "Unpack and clean completed successfully"
