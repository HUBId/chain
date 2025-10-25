#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/provenance_attest.sh --artifact <path> --target <triple> [options]

Emit a SLSA-compatible provenance statement for the provided artifact and sign it
using cosign.

Options:
  --artifact <path>     Path to the artifact to attest (required)
  --target <triple>     Target triple associated with the artifact (required)
  --output-dir <path>   Directory to place the attestation files (default: artifact directory)
  --builder-id <id>     Override the builder identifier (default: derived from GitHub env)
  --subject <name>      Override the subject name recorded in the attestation (default: artifact basename)
  --help                Show this help message and exit
USAGE
}

ARTIFACT=""
TARGET=""
OUTPUT_DIR=""
BUILDER_ID="${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-unknown}/.github/workflows/release.yml"
SUBJECT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifact)
      [[ $# -lt 2 ]] && { echo "error: --artifact requires a value" >&2; exit 1; }
      ARTIFACT="$2"
      shift 2
      ;;
    --target)
      [[ $# -lt 2 ]] && { echo "error: --target requires a value" >&2; exit 1; }
      TARGET="$2"
      shift 2
      ;;
    --output-dir)
      [[ $# -lt 2 ]] && { echo "error: --output-dir requires a value" >&2; exit 1; }
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --builder-id)
      [[ $# -lt 2 ]] && { echo "error: --builder-id requires a value" >&2; exit 1; }
      BUILDER_ID="$2"
      shift 2
      ;;
    --subject)
      [[ $# -lt 2 ]] && { echo "error: --subject requires a value" >&2; exit 1; }
      SUBJECT="$2"
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

if [[ -z "$ARTIFACT" || -z "$TARGET" ]]; then
  echo "error: --artifact and --target are required" >&2
  usage >&2
  exit 1
fi

if [[ ! -f "$ARTIFACT" ]]; then
  echo "error: artifact '$ARTIFACT' not found" >&2
  exit 1
fi

if [[ -z "$OUTPUT_DIR" ]]; then
  OUTPUT_DIR="$(dirname "$ARTIFACT")"
fi

SUBJECT="${SUBJECT:-$(basename "$ARTIFACT")}"
mkdir -p "$OUTPUT_DIR"

HASH_CMD=()
if command -v sha256sum >/dev/null 2>&1; then
  HASH_CMD=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
  HASH_CMD=(shasum -a 256)
else
  echo "error: neither sha256sum nor shasum is available" >&2
  exit 1
fi

digest=$("${HASH_CMD[@]}" "$ARTIFACT" | awk '{print $1}')
started="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
finished="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
attestation="$OUTPUT_DIR/${SUBJECT}.intoto.jsonl"

cat >"$attestation" <<EOF
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "$SUBJECT",
      "digest": {
        "sha256": "$digest"
      }
    }
  ],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "https://slsa.dev/provenance/v1#generic",
      "externalParameters": {
        "target": "$TARGET"
      },
      "internalParameters": {},
      "resolvedDependencies": []
    },
    "runDetails": {
      "builder": {
        "id": "$BUILDER_ID"
      },
      "metadata": {
        "invocationId": "${GITHUB_RUN_ID:-unknown}/${GITHUB_RUN_ATTEMPT:-0}",
        "startedOn": "$started",
        "finishedOn": "$finished"
      }
    }
  }
}
EOF

echo "Wrote provenance statement to $attestation"

if ! command -v cosign >/dev/null 2>&1; then
  echo "error: cosign not found in PATH" >&2
  exit 1
fi

COSIGN_EXPERIMENTAL="${COSIGN_EXPERIMENTAL:-1}" cosign sign-blob \
  --yes \
  --output-signature "${attestation}.sig" \
  --output-certificate "${attestation}.pem" \
  "$attestation"

echo "Signed provenance statement for $SUBJECT"
