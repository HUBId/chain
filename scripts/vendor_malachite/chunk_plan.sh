#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "Usage: $0 <source_archive> [output_plan_file]" >&2
  exit 1
fi

SOURCE_ARCHIVE="$1"
OUTPUT_PLAN="${2:-vendor/malachite/0.4.18/manifest/chunk_plan.json}"
SEGMENT_SIZE_BYTES="${CHUNK_SEGMENT_SIZE_BYTES:-52428800}"

if [[ ! -f "$SOURCE_ARCHIVE" ]]; then
  echo "Source archive '$SOURCE_ARCHIVE' not found" >&2
  exit 2
fi

if ! [[ "$SEGMENT_SIZE_BYTES" =~ ^[0-9]+$ ]]; then
  echo "CHUNK_SEGMENT_SIZE_BYTES must be an integer number of bytes (got '$SEGMENT_SIZE_BYTES')" >&2
  exit 3
fi

FILE_SIZE=$(stat -c%s "$SOURCE_ARCHIVE")

python3 - "$SOURCE_ARCHIVE" "$OUTPUT_PLAN" "$SEGMENT_SIZE_BYTES" "$FILE_SIZE" <<'PY'
import json
import math
import os
import sys

source_archive, output_plan, segment_size_bytes, file_size = sys.argv[1:]
segment_size_bytes = int(segment_size_bytes)
file_size = int(file_size)

if segment_size_bytes <= 0:
    raise SystemExit("Segment size must be greater than zero")

num_segments = max(1, math.ceil(file_size / segment_size_bytes))
plan = []
for index in range(num_segments):
    offset = index * segment_size_bytes
    remaining = file_size - offset
    length = min(segment_size_bytes, remaining)
    plan.append({
        "chunk_name": f"chunk_{index:03d}",
        "offset": offset,
        "length": length,
        "source": os.path.basename(source_archive),
    })

os.makedirs(os.path.dirname(output_plan), exist_ok=True)
with open(output_plan, "w", encoding="utf-8") as handle:
    json.dump({
        "source_archive": os.path.abspath(source_archive),
        "segment_size_bytes": segment_size_bytes,
        "file_size": file_size,
        "chunks": plan,
    }, handle, indent=2)

print(f"Chunk plan written to {output_plan} ({num_segments} segment(s))")
PY
