#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
DEFAULT_VERSION="0.4.18"
VERSION="${MALACHITE_VERSION:-$DEFAULT_VERSION}"
CRATE_NAME="${MALACHITE_CRATE_NAME:-malachite}"
VENDOR_ROOT="${MALACHITE_VENDOR_ROOT:-${REPO_ROOT}/vendor/${CRATE_NAME}/${VERSION}}"
CHUNKS_DIR="${MALACHITE_CHUNKS_DIR:-${VENDOR_ROOT}/chunks}"
MANIFEST_DIR="${MALACHITE_MANIFEST_DIR:-${VENDOR_ROOT}/manifest}"
LOG_DIR="${MALACHITE_LOG_DIR:-${VENDOR_ROOT}/logs}"
LOG_BASENAME="${CRATE_NAME//-/_}_${VERSION//./_}"
LOG_FILE="${MALACHITE_LOG_FILE:-${LOG_DIR}/download_segments_${LOG_BASENAME}.log}"
MANIFEST_FILE="${MALACHITE_MANIFEST_FILE:-${MANIFEST_DIR}/chunks.json}"
PLAN_FILE="${1:-${MALACHITE_PLAN_FILE:-${MANIFEST_DIR}/chunk_plan.json}}"
DEFAULT_SOURCE_URL="https://crates.io/api/v1/crates/${CRATE_NAME}/${VERSION}/download"
SOURCE_URL="${2:-${MALACHITE_SOURCE_URL:-$DEFAULT_SOURCE_URL}}"
USER_AGENT="${MALACHITE_USER_AGENT:-chain-segment-sync/0.1}"
SEGMENT_PREFIX="${MALACHITE_SEGMENT_PREFIX:-${CRATE_NAME}}"
MAX_RETRIES="${MAX_DOWNLOAD_RETRIES:-5}"
RETRY_DELAY="${DOWNLOAD_RETRY_DELAY_SECONDS:-2}"

mkdir -p "$CHUNKS_DIR" "$MANIFEST_DIR" "$LOG_DIR"

log_event() {
  local level="$1"
  shift
  local message="$*"
  local timestamp
  timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  local formatted="[$timestamp] [$level] $message"
  echo "$formatted"
  printf '%s\n' "$formatted" >>"$LOG_FILE"
}

fatal() {
  log_event "ERROR" "$*"
  exit 1
}

if ! command -v curl >/dev/null 2>&1; then
  fatal "curl command not found"
fi

if ! command -v sha256sum >/dev/null 2>&1; then
  fatal "sha256sum command not found"
fi

if [[ ! -f "$PLAN_FILE" ]]; then
  fatal "Chunk plan not found: $PLAN_FILE"
fi

if ! [[ "$MAX_RETRIES" =~ ^[0-9]+$ ]] || (( MAX_RETRIES < 1 )); then
  fatal "MAX_DOWNLOAD_RETRIES must be a positive integer (got '$MAX_RETRIES')"
fi

if ! [[ "$RETRY_DELAY" =~ ^[0-9]+$ ]]; then
  fatal "DOWNLOAD_RETRY_DELAY_SECONDS must be a non-negative integer (got '$RETRY_DELAY')"
fi

read_manifest_entry() {
  local segment_name="$1"
  python3 - "$MANIFEST_FILE" "$segment_name" <<'PY'
import json
import os
import sys

manifest_path, segment_name = sys.argv[1:3]
if not os.path.exists(manifest_path):
    print("\t".join(["", "", "", ""]))
    raise SystemExit(0)
with open(manifest_path, "r", encoding="utf-8") as handle:
    try:
        data = json.load(handle)
    except json.JSONDecodeError:
        print("\t".join(["", "", "", ""]))
        raise SystemExit(0)
segments = data.get("segments")
if not isinstance(segments, list):
    print("\t".join(["", "", "", ""]))
    raise SystemExit(0)
for segment in segments:
    if segment.get("segment_name") == segment_name:
        size = segment.get("size_bytes", "")
        sha256 = segment.get("sha256", "")
        downloaded_at = segment.get("downloaded_at", "")
        length = segment.get("length", segment.get("length_bytes", ""))
        print(f"{size}\t{sha256}\t{downloaded_at}\t{length}")
        break
else:
    print("\t".join(["", "", "", ""]))
PY
}

update_manifest_entry() {
  local segment_name="$1"
  local chunk_name="$2"
  local offset="$3"
  local length="$4"
  local size="$5"
  local sha256="$6"
  local downloaded_at="$7"
  local status="$8"

  python3 - "$MANIFEST_FILE" "$VERSION" "$SOURCE_URL" "$segment_name" "$chunk_name" "$offset" "$length" "$size" "$sha256" "$downloaded_at" "$status" <<'PY'
import json
import os
import sys
from datetime import datetime

(
    manifest_path,
    version,
    source_url,
    segment_name,
    chunk_name,
    offset,
    length,
    size,
    sha256,
    downloaded_at,
    status,
) = sys.argv[1:]
offset = int(offset)
length = int(length)
size = int(size)
now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
if not downloaded_at:
    downloaded_at = now
if os.path.exists(manifest_path):
    try:
        with open(manifest_path, "r", encoding="utf-8") as handle:
            manifest = json.load(handle)
    except json.JSONDecodeError:
        manifest = {}
else:
    manifest = {}
manifest["version"] = version
manifest["source_url"] = source_url
manifest["generated_at"] = now
segments = manifest.setdefault("segments", [])
for entry in segments:
    if entry.get("segment_name") == segment_name:
        entry.update(
            {
                "segment_name": segment_name,
                "chunk_name": chunk_name,
                "offset": offset,
                "length": length,
                "size_bytes": size,
                "sha256": sha256,
                "downloaded_at": downloaded_at,
                "status": status,
            }
        )
        break
else:
    segments.append(
        {
            "segment_name": segment_name,
            "chunk_name": chunk_name,
            "offset": offset,
            "length": length,
            "size_bytes": size,
            "sha256": sha256,
            "downloaded_at": downloaded_at,
            "status": status,
        }
    )
segments.sort(key=lambda item: item.get("segment_name", ""))
with open(manifest_path, "w", encoding="utf-8") as handle:
    json.dump(manifest, handle, indent=2)
    handle.write("\n")
PY
}

mapfile -t CHUNK_LINES < <(python3 - "$PLAN_FILE" <<'PY'
import json
import sys

plan_path = sys.argv[1]
with open(plan_path, "r", encoding="utf-8") as handle:
    plan = json.load(handle)
chunks = plan.get("chunks")
if not isinstance(chunks, list) or not chunks:
    raise SystemExit("Chunk plan must contain a non-empty 'chunks' array")
for index, chunk in enumerate(chunks):
    try:
        offset = int(chunk.get("offset"))
        length = int(chunk.get("length"))
    except (TypeError, ValueError):
        raise SystemExit(f"Invalid offset/length for chunk index {index}")
    if length <= 0:
        raise SystemExit(f"Chunk {index} has non-positive length {length}")
    chunk_name = chunk.get("chunk_name") or f"chunk_{index:03d}"
    print(f"{index}\t{offset}\t{length}\t{chunk_name}")
PY
)

log_event "INFO" "Starting segmented download for ${CRATE_NAME} ${VERSION} using plan ${PLAN_FILE}"
log_event "INFO" "Source URL: ${SOURCE_URL}"

process_chunk() {
  local index="$1"
  local offset="$2"
  local length="$3"
  local chunk_name="$4"

  local segment_name
  segment_name=$(printf "%s-%s.part%03d" "${SEGMENT_PREFIX}" "${VERSION}" "${index}")
  local segment_path="${CHUNKS_DIR}/${segment_name}"
  local range_end=$((offset + length - 1))
  local range_spec="bytes=${offset}-${range_end}"

  log_event "INFO" "Processing ${segment_name} (${chunk_name}) with range ${range_spec}"

  local need_download="false"
  local size
  local sha
  local manifest_size manifest_sha manifest_timestamp manifest_length

  if [[ -f "$segment_path" ]]; then
    log_event "INFO" "Verifying existing segment ${segment_name}"
    size=$(stat -c%s "$segment_path")
    if [[ "$size" -ne "$length" ]]; then
      log_event "WARN" "Existing segment ${segment_name} has size ${size}, expected ${length}; will re-download"
      need_download="true"
    else
      sha=$(sha256sum "$segment_path" | awk '{print $1}')
      IFS=$'\t' read -r manifest_size manifest_sha manifest_timestamp manifest_length < <(read_manifest_entry "$segment_name")
      manifest_size=${manifest_size:-}
      manifest_sha=${manifest_sha:-}
      manifest_timestamp=${manifest_timestamp:-}
      manifest_length=${manifest_length:-}
      if [[ -n "$manifest_length" && "$manifest_length" -ne "$length" ]]; then
        log_event "WARN" "Manifest length for ${segment_name} (${manifest_length}) differs from expected ${length}; will update manifest"
        update_manifest_entry "$segment_name" "$chunk_name" "$offset" "$length" "$size" "$sha" "" "verified"
        log_event "INFO" "Manifest updated for ${segment_name}"
        log_event "INFO" "Segment ${segment_name} verified (sha256=${sha})"
        return 0
      fi
      if [[ -n "$manifest_sha" ]]; then
        if [[ "$manifest_sha" == "$sha" && "$manifest_size" == "$size" ]]; then
          if [[ -z "$manifest_timestamp" ]]; then
            log_event "INFO" "Manifest timestamp missing for ${segment_name}; refreshing entry"
            update_manifest_entry "$segment_name" "$chunk_name" "$offset" "$length" "$size" "$sha" "" "verified"
            log_event "INFO" "Manifest timestamp added for ${segment_name}"
          else
            log_event "INFO" "Segment ${segment_name} already valid (sha256=${sha})"
          fi
          return 0
        else
          log_event "WARN" "Manifest metadata for ${segment_name} differs from actual file; will refresh manifest entry"
          update_manifest_entry "$segment_name" "$chunk_name" "$offset" "$length" "$size" "$sha" "" "verified"
          log_event "INFO" "Manifest refreshed for ${segment_name}"
          return 0
        fi
      else
        log_event "INFO" "Manifest entry missing for ${segment_name}; recording metadata"
        update_manifest_entry "$segment_name" "$chunk_name" "$offset" "$length" "$size" "$sha" "" "verified"
        log_event "INFO" "Manifest recorded for existing segment ${segment_name}"
        return 0
      fi
    fi
  else
    need_download="true"
  fi

  if [[ "$need_download" != "true" ]]; then
    return 0
  fi

  local attempt=1
  local downloaded_hash=""
  local downloaded_size=0
  while (( attempt <= MAX_RETRIES )); do
    log_event "INFO" "Downloading ${segment_name} (attempt ${attempt}/${MAX_RETRIES}, range ${range_spec})"
    local tmp_file
    tmp_file=$(mktemp "${segment_path}.tmp.XXXXXX")
    if curl --fail --location --silent --show-error --user-agent "$USER_AGENT" --range "$range_spec" "$SOURCE_URL" --output "$tmp_file"; then
      downloaded_size=$(stat -c%s "$tmp_file")
      if [[ "$downloaded_size" -ne "$length" ]]; then
        log_event "WARN" "Downloaded size for ${segment_name} was ${downloaded_size}, expected ${length}"
        rm -f "$tmp_file"
        if (( attempt < MAX_RETRIES )); then
          log_event "INFO" "Retrying ${segment_name} after ${RETRY_DELAY}s"
          sleep "$RETRY_DELAY"
          ((attempt++))
          continue
        else
          fatal "Failed to download ${segment_name}: size mismatch after ${MAX_RETRIES} attempt(s)"
        fi
      fi
      downloaded_hash=$(sha256sum "$tmp_file" | awk '{print $1}')
      mv "$tmp_file" "$segment_path"
      break
    else
      local exit_code=$?
      rm -f "$tmp_file"
      if (( attempt < MAX_RETRIES )); then
        log_event "WARN" "Attempt ${attempt}/${MAX_RETRIES} for ${segment_name} failed (exit ${exit_code}); retrying in ${RETRY_DELAY}s"
        sleep "$RETRY_DELAY"
        ((attempt++))
        continue
      else
        fatal "Download failed for ${segment_name} after ${MAX_RETRIES} attempts (last exit ${exit_code})"
      fi
    fi
  done

  if [[ -z "$downloaded_hash" ]]; then
    fatal "Download failed for ${segment_name}; no data retrieved"
  fi

  local timestamp
  timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  update_manifest_entry "$segment_name" "$chunk_name" "$offset" "$length" "$downloaded_size" "$downloaded_hash" "$timestamp" "downloaded"
  log_event "INFO" "Segment ${segment_name} downloaded successfully (size=${downloaded_size}, sha256=${downloaded_hash})"
}

for line in "${CHUNK_LINES[@]}"; do
  IFS=$'\t' read -r index offset length chunk_name <<<"$line"
  process_chunk "$index" "$offset" "$length" "$chunk_name"
done

log_event "INFO" "All segments processed successfully"
