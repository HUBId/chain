#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)
VERSION="${MALACHITE_VERSION:-0.4.18}"

KEEP_CHUNKS=${MALACHITE_KEEP_CHUNKS:-0}

CRATES=(
  malachite
  malachite-base
  malachite-nz
  malachite-q
  malachite-float
)

declare -A VERIFY_RESULTS=()

log() {
  local level="$1"
  shift
  local message="$*"
  local timestamp
  timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  printf '[%s] [%s] %s\n' "$timestamp" "$level" "$message"
}

cleanup_chunks() {
  local crate_name="$1"
  local directory="$2"
  local archive_path="$3"

  if [[ "$KEEP_CHUNKS" =~ ^(1|true|yes)$ ]]; then
    log INFO "Überspringe Bereinigung der Chunk-Dateien für ${crate_name} (KEEP_CHUNKS=${KEEP_CHUNKS})"
    return
  fi

  if [[ ! -d "$directory" ]]; then
    return
  fi

  shopt -s nullglob
  local removed=0
  for chunk_file in "$directory"/*; do
    if [[ -f "$chunk_file" && "${chunk_file##*/}" != ".gitkeep" ]]; then
      rm -f "$chunk_file"
      ((removed++))
    fi
  done
  shopt -u nullglob

  if (( removed > 0 )); then
    log INFO "Bereinigte ${removed} Chunk-Datei(en) unter ${directory}"
  else
    log INFO "Keine temporären Chunk-Dateien unter ${directory} gefunden"
  fi

  if [[ -n "$archive_path" && -f "$archive_path" ]]; then
    rm -f "$archive_path"
    log INFO "Temporäres Crate-Archiv entfernt (${archive_path})"
  fi
}

for crate in "${CRATES[@]}"; do
  vendor_root="${REPO_ROOT}/vendor/${crate}/${VERSION}"
  manifest_dir="${vendor_root}/manifest"
  log_dir="${vendor_root}/logs"
  chunks_dir="${vendor_root}/chunks"
  plan_file="${manifest_dir}/chunk_plan.json"
  source_url="https://crates.io/api/v1/crates/${crate}/${VERSION}/download"
  case "${crate}" in
    malachite|malachite-base)
      segment_prefix="malachite"
      ;;
    *)
      segment_prefix="${crate}"
      ;;
  esac

  log INFO "Processing ${crate} ${VERSION}"

  if [[ ! -f "${plan_file}" ]]; then
    log ERROR "Chunk plan fehlt: ${plan_file}"
    exit 1
  fi

  env \
    MALACHITE_CRATE_NAME="${crate}" \
    MALACHITE_VERSION="${VERSION}" \
    MALACHITE_VENDOR_ROOT="${vendor_root}" \
    MALACHITE_MANIFEST_DIR="${manifest_dir}" \
    MALACHITE_LOG_DIR="${log_dir}" \
    MALACHITE_CHUNKS_DIR="${chunks_dir}" \
    MALACHITE_PLAN_FILE="${plan_file}" \
    MALACHITE_SOURCE_URL="${source_url}" \
    MALACHITE_SEGMENT_PREFIX="${segment_prefix}" \
    bash "${SCRIPT_DIR}/download_segments.sh"

  env \
    MALACHITE_CRATE_NAME="${crate}" \
    MALACHITE_VERSION="${VERSION}" \
    MALACHITE_VENDOR_ROOT="${vendor_root}" \
    MALACHITE_MANIFEST_DIR="${manifest_dir}" \
    MALACHITE_LOG_DIR="${log_dir}" \
    MALACHITE_CHUNKS_DIR="${chunks_dir}" \
    MALACHITE_SEGMENT_PREFIX="${segment_prefix}" \
    bash "${SCRIPT_DIR}/merge_segments.sh"

  if python3 "${SCRIPT_DIR}/verify_extracted_files.py" \
    --package "${crate}" \
    --version "${VERSION}" \
    --vendor-root "${vendor_root}" \
    --manifest-dir "${manifest_dir}" \
    --log-dir "${log_dir}" \
    --src-dir "${vendor_root}/src" \
    --report-json "${manifest_dir}/integrity_report.json" \
    --report-text "${log_dir}/integrity_report.txt" \
    --reference-manifest "${manifest_dir}/reference_hashes.json"; then
    VERIFY_RESULTS["${crate}"]="pass"
  else
    status=$?
    VERIFY_RESULTS["${crate}"]="fail (${status})"
    log WARN "Verifikation fehlgeschlagen (Exit-Code ${status})"
  fi

  cleanup_chunks "${crate}" "${chunks_dir}" "${vendor_root}/${crate}-${VERSION}.crate"

  log INFO "Fertig: ${crate} ${VERSION}"
  echo
done

log INFO "Zusammenfassung der Verifikationsergebnisse:"
for crate in "${CRATES[@]}"; do
  result=${VERIFY_RESULTS["${crate}"]:-n/a}
  log INFO "  ${crate}: ${result}"
done
