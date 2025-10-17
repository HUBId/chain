#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
DEFAULT_VERSION="0.4.18"
VERSION="${MALACHITE_VERSION:-$DEFAULT_VERSION}"
CRATE_NAME="${MALACHITE_CRATE_NAME:-malachite}"
ARCHIVE_NAME="${CRATE_NAME}-${VERSION}.crate"
VENDOR_ROOT="${MALACHITE_VENDOR_ROOT:-${REPO_ROOT}/vendor/${CRATE_NAME}/${VERSION}}"
CHUNKS_DIR="${MALACHITE_CHUNKS_DIR:-${VENDOR_ROOT}/chunks}"
MANIFEST_DIR="${MALACHITE_MANIFEST_DIR:-${VENDOR_ROOT}/manifest}"
LOG_DIR="${MALACHITE_LOG_DIR:-${VENDOR_ROOT}/logs}"
OUTPUT_FILE="${MALACHITE_OUTPUT_FILE:-${VENDOR_ROOT}/${ARCHIVE_NAME}}"
LOG_BASENAME="${CRATE_NAME//-/_}_${VERSION//./_}"
LOG_FILE="${MALACHITE_LOG_FILE:-${LOG_DIR}/merge_segments_${LOG_BASENAME}.log}"
MANIFEST_FILE="${MALACHITE_MANIFEST_FILE:-${MANIFEST_DIR}/chunks.json}"
REFERENCE_HASH_FILE="${MALACHITE_REFERENCE_HASH_FILE:-${MANIFEST_DIR}/reference_hash.txt}"
REPORT_FILE="${MALACHITE_REPORT_FILE:-${MANIFEST_DIR}/merge_report.json}"
CRATES_API_URL="https://crates.io/api/v1/crates/${CRATE_NAME}/${VERSION}"
USER_AGENT="chain-merge-script/0.1 (https://github.com/chain)"

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
  log_event "ERROR" "Merge aborted"
  exit 1
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    fatal "Required command '$1' not found"
  fi
}

require_command curl
require_command python3
require_command sha256sum
require_command cat

if [[ ! -f "$MANIFEST_FILE" ]]; then
  fatal "Manifest file not found: $MANIFEST_FILE"
fi

log_event "INFO" "Loading manifest for ${CRATE_NAME} ${VERSION} from $MANIFEST_FILE"

mapfile -t SEGMENT_LINES < <(python3 - "$MANIFEST_FILE" <<'PY'
import json
import sys

manifest_path = sys.argv[1]
with open(manifest_path, "r", encoding="utf-8") as handle:
    try:
        manifest = json.load(handle)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Manifest is not valid JSON: {exc}")
segments = manifest.get("segments")
if not isinstance(segments, list) or not segments:
    raise SystemExit("Manifest does not contain any segments")

def sort_key(segment):
    if isinstance(segment, dict):
        if "index" in segment:
            try:
                return int(segment["index"])
            except (TypeError, ValueError):
                pass
        if "offset" in segment:
            try:
                return int(segment["offset"])
            except (TypeError, ValueError):
                pass
        name = segment.get("segment_name")
        if isinstance(name, str):
            return name
    return 0
segments_sorted = sorted(segments, key=sort_key)
for segment in segments_sorted:
    if not isinstance(segment, dict):
        raise SystemExit("Segment entry is not a JSON object")
    name = segment.get("segment_name")
    if not isinstance(name, str) or not name:
        raise SystemExit("Segment entry missing 'segment_name'")
    index = segment.get("index")
    offset = segment.get("offset")
    length = segment.get("length") or segment.get("length_bytes")
    print("\t".join([
        str(index) if index is not None else "",
        name,
        str(offset) if offset is not None else "",
        str(length) if length is not None else "",
    ]))
PY
)

if (( ${#SEGMENT_LINES[@]} == 0 )); then
  fatal "No segments available for merging"
fi

SEGMENT_PATHS=()
log_event "INFO" "Validating segment files"
for line in "${SEGMENT_LINES[@]}"; do
  IFS=$'\t' read -r index segment_name offset length <<<"$line"
  if [[ -z "$segment_name" ]]; then
    fatal "Encountered segment with empty name"
  fi
  local_path="${CHUNKS_DIR}/${segment_name}"
  if [[ ! -f "$local_path" ]]; then
    fatal "Segment file missing: $local_path"
  fi
  SEGMENT_PATHS+=("$local_path")
  log_event "INFO" "Queued segment ${segment_name} (index=${index:-?} offset=${offset:-?} length=${length:-?})"
done

log_event "INFO" "Fetching reference checksum from crates.io"
reference_hash=$(python3 - "$CRATES_API_URL" "$USER_AGENT" <<'PY'
import json
import sys
import urllib.request

url, user_agent = sys.argv[1:3]
request = urllib.request.Request(url, headers={"User-Agent": user_agent})
with urllib.request.urlopen(request) as response:
    if response.status != 200:
        raise SystemExit(f"Failed to fetch crate metadata: HTTP {response.status}")
    data = json.load(response)
version = data.get("version")
if not isinstance(version, dict):
    raise SystemExit("Crate metadata missing 'version' object")
checksum = version.get("checksum")
if not isinstance(checksum, str) or not checksum:
    raise SystemExit("Crate metadata missing checksum")
print(checksum)
PY
) || fatal "Unable to retrieve reference checksum"

printf '%s\n' "$reference_hash" >"$REFERENCE_HASH_FILE"
log_event "INFO" "Stored reference checksum at $REFERENCE_HASH_FILE"

log_event "INFO" "Merging ${#SEGMENT_PATHS[@]} segments into $OUTPUT_FILE"
cat "${SEGMENT_PATHS[@]}" >"$OUTPUT_FILE"

actual_hash=$(sha256sum "$OUTPUT_FILE" | awk '{print $1}')
log_event "INFO" "Computed archive checksum: ${actual_hash}"

timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
status="success"
if [[ "$actual_hash" != "$reference_hash" ]]; then
  status="mismatch"
  log_event "ERROR" "Checksum mismatch: expected ${reference_hash}, got ${actual_hash}"
  log_event "ERROR" "Merge failed"
else
  log_event "INFO" "Checksum verification succeeded"
fi

python3 - "$REPORT_FILE" "$timestamp" "$reference_hash" "$actual_hash" "$status" "$VERSION" "$OUTPUT_FILE" <<'PY'
import json
import sys

report_path, timestamp, expected_hash, actual_hash, status, version, output_file = sys.argv[1:8]
report = {
    "version": version,
    "timestamp": timestamp,
    "expected_sha256": expected_hash,
    "actual_sha256": actual_hash,
    "status": status,
    "output_file": output_file,
}
with open(report_path, "w", encoding="utf-8") as handle:
    json.dump(report, handle, indent=2)
    handle.write("\n")
PY

log_event "INFO" "Merge report written to $REPORT_FILE"

if [[ "$status" != "success" ]]; then
  exit 2
fi

log_event "INFO" "Merge completed successfully"
