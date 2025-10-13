#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE' >&2
Usage: vendor_malachite_base.sh <crate> <version> <chunk_size_bytes> <staging_root> <vendor_dir>

crate               Name of the crate to download (e.g. malachite-base)
version             Crate version to download (e.g. 0.4.18)
chunk_size_bytes    Size for each download segment in bytes (e.g. 1048576)
staging_root        Directory under which temporary work directories will be created
vendor_dir          Destination directory for the vendored crate sources
USAGE
}

if [[ $# -ne 5 ]]; then
  usage
  exit 1
fi

crate=$1
version=$2
chunk_size=$3
staging_root=$4
vendor_dir=$5

if ! [[ ${chunk_size} =~ ^[0-9]+$ ]] || [[ ${chunk_size} -le 0 ]]; then
  echo "error: chunk size must be a positive integer (bytes)" >&2
  exit 1
fi

chunk_size=$((chunk_size))

required_tools=(curl sha256sum tar python3 rsync)
for tool in "${required_tools[@]}"; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    echo "error: required tool '${tool}' is not available" >&2
    exit 1
  fi
done

abs_path() {
  python3 - "$1" <<'PY'
import os
import sys
print(os.path.abspath(sys.argv[1]))
PY
}

staging_root=$(abs_path "${staging_root}")
vendor_dir=$(abs_path "${vendor_dir}")
mkdir -p "${staging_root}" "${vendor_dir}"

vendor_parent=$(dirname "${vendor_dir}")
logs_dir="${vendor_parent}/logs"
mkdir -p "${logs_dir}"
log_file="${logs_dir}/${crate}-${version}-$(date -u +"%Y%m%dT%H%M%SZ").log"

touch "${log_file}"
exec > >(tee -a "${log_file}")
exec 2> >(tee -a "${log_file}" >&2)

echo "[info] Starting segmented download for ${crate} ${version}" >&2

api_base="https://crates.io/api/v1/crates/${crate}/${version}"
download_endpoint="${api_base}/download"

set +e
canonical_url=$(curl -sSIL -o /dev/null -w '%{url_effective}' "${download_endpoint}")
status=$?
set -e
if [[ ${status} -ne 0 || -z ${canonical_url} ]]; then
  echo "error: failed to resolve canonical download URL" >&2
  exit 1
fi

echo "[info] Canonical archive URL: ${canonical_url}" >&2

archive_size=$(curl -sSI "${canonical_url}" | awk 'tolower($1)=="content-length:" {print $2}' | tr -d '\r')
if [[ -z ${archive_size} ]]; then
  echo "error: unable to determine archive size from server" >&2
  exit 1
fi

if ! [[ ${archive_size} =~ ^[0-9]+$ ]]; then
  echo "error: invalid archive size reported by server: ${archive_size}" >&2
  exit 1
fi

archive_size=$((archive_size))

official_checksum=$(curl -sS "${api_base}" | python3 -c 'import json,sys; data=json.load(sys.stdin); print(data["version"]["checksum"])')
if [[ -z ${official_checksum} ]]; then
  echo "error: unable to determine official crate checksum" >&2
  exit 1
fi

echo "[info] Archive size: ${archive_size} bytes" >&2

echo "[info] Official checksum: ${official_checksum}" >&2

workdir=$(mktemp -d "${staging_root}/${crate}-${version}.XXXXXX")
trap 'rm -rf "${workdir}"' EXIT

parts_dir="${workdir}/parts"
archive_path="${workdir}/${crate}-${version}.crate"
extract_dir="${workdir}/extracted"
mkdir -p "${parts_dir}" "${extract_dir}"

manifest_path="${vendor_dir}/manifest.json"
integrity_report_path="${vendor_dir}/integrity-report.json"

python3 - <<PY "${manifest_path}" "${crate}" "${version}" "${chunk_size}" "${canonical_url}" "${official_checksum}"
import json
import sys
from datetime import datetime, timezone
path, crate, version, chunk_size, url, checksum = sys.argv[1:7]
manifest = {
    "crate": crate,
    "version": version,
    "chunk_size": int(chunk_size),
    "download_url": url,
    "expected_archive_sha256": checksum,
    "generated_at": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
    "segments": []
}
with open(path, 'w', encoding='utf-8') as handle:
    json.dump(manifest, handle, indent=2)
    handle.write('\n')
PY

segment_index=0
start=0

declare -a part_files=()

while [[ ${start} -lt ${archive_size} ]]; do
  end=$((start + chunk_size - 1))
  if [[ ${end} -ge ${archive_size} ]]; then
    end=$((archive_size - 1))
  fi
  expected_size=$((end - start + 1))
  part_name=$(printf "%s.part%02d" "${crate}-${version}" "${segment_index}")
  part_file="${parts_dir}/${part_name}"
  tmp_file="${part_file}.tmp"

  echo "[info] Downloading bytes ${start}-${end} to ${part_file}" >&2

  attempt=0
  success=0
  while [[ ${attempt} -lt 5 && ${success} -eq 0 ]]; do
    attempt=$((attempt + 1))
    set +e
    curl -sS --fail -r "${start}-${end}" "${canonical_url}" -o "${tmp_file}"
    curl_status=$?
    set -e
    if [[ ${curl_status} -ne 0 ]]; then
      echo "[warn] Attempt ${attempt} failed for segment ${segment_index}; retrying" >&2
      rm -f "${tmp_file}"
      sleep 1
      continue
    fi

    actual_size=$(stat -c%s "${tmp_file}")
    if [[ ${actual_size} -ne ${expected_size} ]]; then
      echo "[warn] Segment ${segment_index} size mismatch (expected ${expected_size}, got ${actual_size}); retrying" >&2
      rm -f "${tmp_file}"
      sleep 1
      continue
    fi

    checksum=$(sha256sum "${tmp_file}" | awk '{print $1}')
    verify=$(sha256sum "${tmp_file}" | awk '{print $1}')
    if [[ ${checksum} != ${verify} ]]; then
      echo "[warn] Segment ${segment_index} checksum mismatch; retrying" >&2
      rm -f "${tmp_file}"
      sleep 1
      continue
    fi

    success=1
  done

  if [[ ${success} -eq 0 ]]; then
    echo "error: failed to download segment ${segment_index}" >&2
    exit 1
  fi

  mv "${tmp_file}" "${part_file}"
  part_files+=("${part_file}")

  timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

  python3 - <<PY "${manifest_path}" "${segment_index}" "${start}" "${end}" "${expected_size}" "${checksum}" "${timestamp}"
import json
import sys
path, index, start, end, size, checksum, timestamp = sys.argv[1:8]
with open(path, 'r', encoding='utf-8') as handle:
    data = json.load(handle)
segment = {
    "index": int(index),
    "range_start": int(start),
    "range_end": int(end),
    "size": int(size),
    "sha256": checksum,
    "timestamp": timestamp
}
data.setdefault('segments', []).append(segment)
with open(path, 'w', encoding='utf-8') as handle:
    json.dump(data, handle, indent=2)
    handle.write('\n')
PY

  segment_index=$((segment_index + 1))
  start=$((end + 1))
done

if [[ ${#part_files[@]} -eq 0 ]]; then
  echo "error: no segments were downloaded" >&2
  exit 1
fi

echo "[info] Combining ${#part_files[@]} segments into archive" >&2

sorted_parts=("${part_files[@]}")
IFS=$'\n' sorted_parts=($(printf '%s\n' "${sorted_parts[@]}" | sort))
unset IFS

cat "${sorted_parts[@]}" > "${archive_path}"

merged_checksum=$(sha256sum "${archive_path}" | awk '{print $1}')

echo "[info] Merged archive checksum: ${merged_checksum}" >&2

if [[ ${merged_checksum} != ${official_checksum} ]]; then
  echo "error: merged archive checksum mismatch" >&2
  exit 1
fi

echo "[info] Archive verified successfully" >&2

python3 - <<PY "${manifest_path}" "${merged_checksum}"
import json
import sys
from datetime import datetime, timezone
path, checksum = sys.argv[1:3]
with open(path, 'r', encoding='utf-8') as handle:
    data = json.load(handle)
data['merged_archive_sha256'] = checksum
data['completed_at'] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
with open(path, 'w', encoding='utf-8') as handle:
    json.dump(data, handle, indent=2)
    handle.write('\n')
PY

tar -xzf "${archive_path}" -C "${extract_dir}"

source_dir="${extract_dir}/${crate}-${version}"
if [[ ! -d ${source_dir} ]]; then
  echo "error: expected extracted directory ${source_dir} to exist" >&2
  exit 1
fi

echo "[info] Pruning non-build artifacts" >&2
rm -rf "${source_dir}/.git" \
       "${source_dir}/.github" \
       "${source_dir}/target"
rm -f "${source_dir}/.cargo-ok"

rsync -a --delete \
  --exclude 'manifest.json' \
  --exclude 'integrity-report.json' \
  "${source_dir}/" "${vendor_dir}/"

echo "[info] Computing integrity report" >&2

python3 - <<'PY' "${archive_path}" "${source_dir}" "${integrity_report_path}"
import hashlib
import json
import os
import sys
import tarfile
from datetime import datetime, timezone

def sha256_file(path):
    hasher = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            hasher.update(chunk)
    return hasher.hexdigest()

def sha256_bytes(data):
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.hexdigest()

archive_path, source_dir, report_path = sys.argv[1:4]
archive = tarfile.open(archive_path, 'r:*')
try:
    archive_members = {
        member.name: member for member in archive.getmembers() if member.isfile()
    }
    report_entries = []
    prefix = os.path.basename(source_dir)
    for root, _, files in os.walk(source_dir):
        for filename in files:
            disk_path = os.path.join(root, filename)
            rel_path = os.path.relpath(disk_path, source_dir)
            member_name = f"{prefix}/{rel_path}"
            disk_size = os.path.getsize(disk_path)
            disk_checksum = sha256_file(disk_path)
            archive_checksum = None
            archive_size = None
            matches = False
            member = archive_members.get(member_name)
            if member is not None:
                extracted = archive.extractfile(member)
                if extracted is not None:
                    with extracted:
                        data = extracted.read()
                    archive_size = len(data)
                    archive_checksum = sha256_bytes(data)
                    matches = (archive_checksum == disk_checksum)
            entry = {
                "path": rel_path,
                "disk_size": disk_size,
                "disk_sha256": disk_checksum,
                "archive_size": archive_size,
                "archive_sha256": archive_checksum,
                "matches_archive": matches
            }
            report_entries.append(entry)
finally:
    archive.close()

report = {
    "generated_at": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
    "archive_path": os.path.basename(archive_path),
    "files": sorted(report_entries, key=lambda entry: entry["path"])
}
with open(report_path, 'w', encoding='utf-8') as handle:
    json.dump(report, handle, indent=2)
    handle.write('\n')
PY

echo "[info] Integrity report stored at ${integrity_report_path}" >&2

echo "[info] Completed segmented vendoring for ${crate} ${version}" >&2
