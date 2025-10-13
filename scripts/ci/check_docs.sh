#!/usr/bin/env bash
set -euo pipefail

# Ensure we run from repository root
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
TOOLCHAIN_FILE="$REPO_ROOT/rust-toolchain.toml"
RELEASE_NOTES_FILE="$REPO_ROOT/RELEASE_NOTES.md"

if [[ ! -f "$TOOLCHAIN_FILE" ]]; then
  echo "rust-toolchain.toml not found at $TOOLCHAIN_FILE" >&2
  exit 1
fi

if [[ ! -f "$RELEASE_NOTES_FILE" ]]; then
  echo "RELEASE_NOTES.md not found at $RELEASE_NOTES_FILE" >&2
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

exit 0
