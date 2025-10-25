#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/prepare_changelog.sh --tag <tag> --output <file>

Generate release notes for the supplied tag using git-cliff and enforce
required section gates.
USAGE
}

TAG=""
OUTPUT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag)
      [[ $# -lt 2 ]] && { echo "error: --tag requires a value" >&2; exit 1; }
      TAG="$2"
      shift 2
      ;;
    --output)
      [[ $# -lt 2 ]] && { echo "error: --output requires a value" >&2; exit 1; }
      OUTPUT="$2"
      shift 2
      ;;
    --help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument '$1'" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "$TAG" || -z "$OUTPUT" ]]; then
  echo "error: --tag and --output are required" >&2
  usage >&2
  exit 1
fi

if [[ ! "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+.*$ ]]; then
  echo "error: tag '$TAG' does not look like a SemVer tag (expected vMAJOR.MINOR.PATCH)" >&2
  exit 1
fi

if ! command -v git-cliff >/dev/null 2>&1; then
  echo "error: git-cliff must be installed" >&2
  exit 1
fi

if ! git rev-parse "$TAG" >/dev/null 2>&1; then
  echo "error: tag '$TAG' does not exist" >&2
  exit 1
fi

TMP_OUTPUT="$(mktemp)"
trap 'rm -f "$TMP_OUTPUT"' EXIT

git cliff --config cliff.toml --tag "$TAG" >"$TMP_OUTPUT"

if ! grep -q '^\s*- ' "$TMP_OUTPUT"; then
  echo "error: git-cliff did not produce any changelog entries for $TAG" >&2
  exit 1
fi

extract_section() {
  local heading="$1"
  local file="$2"
  awk -v heading="$heading" '
    /^### / { current = $0 }
    current ~ heading { if (!/^### /) print }
  ' "$file" | sed '/^\s*$/d' | sed 's/^\s\+- /- /'
}

FEATURES=$(extract_section "<!-- 0 -->" "$TMP_OUTPUT")
FIXES=$(extract_section "<!-- 1 -->" "$TMP_OUTPUT")
SECURITY=$(extract_section "<!-- 8 -->" "$TMP_OUTPUT")
BREAKING=$(grep '\[\*\*breaking\*\*\]' "$TMP_OUTPUT" | sed 's/^\s\+- /- /' || true)

mkdir -p "$(dirname "$OUTPUT")"
cat >"$OUTPUT" <<EOF
# Release notes for $TAG

## ✨ Features
${FEATURES:-_No feature changes recorded._}

## 🐛 Fixes
${FIXES:-_No fixes recorded._}

## ⚠️ Breaking Changes
${BREAKING:-_No breaking changes recorded._}

## 🛡️ Security
${SECURITY:-_No security updates recorded._}

## ⬆️ Upgrade Notes
_Consult the operator documentation for manual upgrade steps._
EOF

for heading in "Features" "Fixes" "Breaking" "Security" "Upgrade"; do
  if ! grep -q "## .*${heading}" "$OUTPUT"; then
    echo "error: required heading '${heading}' missing from release notes" >&2
    exit 1
  fi
done
