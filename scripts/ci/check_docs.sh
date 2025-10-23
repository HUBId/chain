#!/usr/bin/env bash
set -euo pipefail

# Ensure we run from repository root
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
TOOLCHAIN_FILE="$REPO_ROOT/rust-toolchain.toml"
RELEASE_NOTES_FILE="$REPO_ROOT/RELEASE_NOTES.md"
RPC_GUIDE_FILE="$REPO_ROOT/docs/rpc_cli_operator_guide.md"
declare -a RPC_GUIDE_REFERENCES=(
  "README.md"
  "docs/deployment_observability.md"
  "docs/development/tooling.md"
)
declare -a VALIDATOR_GUIDES=(
  "$REPO_ROOT/docs/validator_quickstart.md"
  "$REPO_ROOT/docs/validator_troubleshooting.md"
)

lint_markdown_files() {
  if command -v markdownlint >/dev/null 2>&1; then
    markdownlint "$@"
    return
  fi

  python3 - "$@" <<'PY'
import pathlib
import sys

def lint(path: pathlib.Path) -> int:
    if not path.exists():
        print(f"markdown lint: missing file {path}", file=sys.stderr)
        return 1

    errors = 0
    data = path.read_bytes()
    if data and not data.endswith(b"\n"):
        print(f"{path}: file must end with a newline", file=sys.stderr)
        errors += 1

    for lineno, raw_line in enumerate(data.splitlines(), start=1):
        line = raw_line.decode('utf-8', errors='ignore')
        if line.rstrip() != line:
            print(f"{path}:{lineno}: trailing whitespace", file=sys.stderr)
            errors += 1
        if '\t' in line:
            print(f"{path}:{lineno}: tab character found", file=sys.stderr)
            errors += 1
        if line.startswith('#'):
            idx = 0
            while idx < len(line) and line[idx] == '#':
                idx += 1
            if idx == len(line) or line[idx] != ' ':
                print(f"{path}:{lineno}: headings must include a space after '#'", file=sys.stderr)
                errors += 1
    return errors

exit_code = 0
for name in sys.argv[1:]:
    exit_code += lint(pathlib.Path(name))

sys.exit(1 if exit_code else 0)
PY
}

if [[ ! -f "$TOOLCHAIN_FILE" ]]; then
  echo "rust-toolchain.toml not found at $TOOLCHAIN_FILE" >&2
  exit 1
fi

if [[ ! -f "$RELEASE_NOTES_FILE" ]]; then
  echo "RELEASE_NOTES.md not found at $RELEASE_NOTES_FILE" >&2
  exit 1
fi

if [[ ! -f "$RPC_GUIDE_FILE" ]]; then
  echo "docs/rpc_cli_operator_guide.md not found at $RPC_GUIDE_FILE" >&2
  exit 1
fi

channel_line=$(grep -E '^channel\s*=\s*"' "$TOOLCHAIN_FILE" || true)
if [[ -z "${channel_line}" ]]; then
  echo "Failed to find channel in rust-toolchain.toml" >&2
  exit 1
fi

channel=$(sed -E 's/^channel\s*=\s*"([^"]+)".*/\1/' <<<"$channel_line")
if [[ -z "$channel" ]]; then
  echo "Failed to parse channel value from rust-toolchain.toml" >&2
  exit 1
fi

if ! grep -q "\`$channel\`" "$RELEASE_NOTES_FILE"; then
  echo "RELEASE_NOTES.md is missing the current toolchain channel '$channel'" >&2
  exit 1
fi

for reference in "${RPC_GUIDE_REFERENCES[@]}"; do
  reference_path="$REPO_ROOT/$reference"
  if [[ ! -f "$reference_path" ]]; then
    echo "Expected RPC CLI guide reference file missing: $reference_path" >&2
    exit 1
  fi
  if ! grep -q "rpc_cli_operator_guide" "$reference_path"; then
    echo "${reference} is missing a reference to docs/rpc_cli_operator_guide.md" >&2
    exit 1
  fi
done

for guide in "${VALIDATOR_GUIDES[@]}"; do
  if [[ ! -f "$guide" ]]; then
    echo "Expected validator guide missing: $guide" >&2
    exit 1
  fi
done

lint_markdown_files "${VALIDATOR_GUIDES[@]}"

for guide in "${VALIDATOR_GUIDES[@]}"; do
  guide_rel="docs/$(basename "$guide")"
  if ! grep -q "$guide_rel" "$RELEASE_NOTES_FILE"; then
    echo "RELEASE_NOTES.md is missing a reference to $guide_rel" >&2
    exit 1
  fi
done

exit 0
