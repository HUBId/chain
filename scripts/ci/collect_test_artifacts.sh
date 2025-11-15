#!/usr/bin/env bash
# Collects CI-friendly logs and audit files and redacts obvious secrets before
# uploading them as workflow artifacts.
set -euo pipefail

die() {
  echo "usage: $0 <destination> [paths...]" >&2
  exit 64
}

if [[ $# -lt 1 ]]; then
  die
fi

dest=$1
shift

if [[ $# -gt 0 ]]; then
  roots=("$@")
else
  roots=(logs)
fi

mkdir -p "${dest}"

sanitize_and_copy() {
  local src=$1
  local rel=$2
  local dst="${dest}/${rel}"
  mkdir -p "$(dirname "${dst}")"
  python3 - "$src" "$dst" <<'PY'
import pathlib
import re
import sys

src = pathlib.Path(sys.argv[1])
dst = pathlib.Path(sys.argv[2])
pattern = re.compile(
    r"((?i)(mnemonic|seed|secret|token|api[_-]?key|password|private(?:_key)?|bearer)[\s:=]+)([^\s]+)"
)
with src.open("r", encoding="utf-8", errors="ignore") as handle:
    data = handle.read()
redacted = pattern.sub(lambda match: match.group(1) + "***REDACTED***", data)
with dst.open("w", encoding="utf-8") as handle:
    handle.write(redacted)
PY
}

for root in "${roots[@]}"; do
  if [[ ! -e "${root}" ]]; then
    continue
  fi
  while IFS= read -r -d '' file; do
    rel=${file#./}
    rel=${rel#"$PWD/"}
    rel=${rel#/}
    sanitize_and_copy "${file}" "${rel}"
  done < <(find "${root}" -type f \
    \( -name '*.log' -o -name '*.json' -o -name '*.jsonl' -o -name '*.txt' -o -name '*.md' -o -name '*.csv' \) \
    -print0)
done
