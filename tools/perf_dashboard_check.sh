#!/usr/bin/env bash
set -euo pipefail

print_usage() {
  cat <<'USAGE'
Usage: tools/perf_dashboard_check.sh [--manifest PATH] [--write]

Fetches Grafana dashboard exports listed in the manifest and either verifies
that the committed JSON matches the live dashboards (--verify, default mode)
or rewrites the exports in-place (--write).

Environment variables:
  PERF_GRAFANA_URL       Base URL of the Grafana instance (e.g. https://grafana.example.com)
  PERF_GRAFANA_API_KEY   API token with dashboard:read permissions
USAGE
}

MODE="verify"
MANIFEST="docs/performance_dashboards.json"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --manifest)
      if [[ $# -lt 2 ]]; then
        echo "--manifest requires a path argument" >&2
        exit 1
      fi
      MANIFEST="$2"
      shift 2
      ;;
    --write)
      MODE="write"
      shift
      ;;
    -h|--help)
      print_usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      print_usage >&2
      exit 1
      ;;
  esac
done

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/.." && pwd)

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required" >&2
  exit 1
fi

if [[ "${MANIFEST:0:1}" != "/" ]]; then
  MANIFEST="${REPO_ROOT}/${MANIFEST}"
fi

if [[ ! -f "${MANIFEST}" ]]; then
  echo "Manifest not found: ${MANIFEST}" >&2
  exit 1
fi

PERF_GRAFANA_URL=${PERF_GRAFANA_URL:-}
PERF_GRAFANA_API_KEY=${PERF_GRAFANA_API_KEY:-}

if [[ -z "${PERF_GRAFANA_URL}" || -z "${PERF_GRAFANA_API_KEY}" ]]; then
  echo "PERF_GRAFANA_URL and PERF_GRAFANA_API_KEY must be set" >&2
  exit 1
fi

BASE_URL=${PERF_GRAFANA_URL%/}
STATUS=0

while IFS= read -r entry; do
  uid=$(jq -r '.uid' <<<"${entry}")
  output=$(jq -r '.output' <<<"${entry}")
  title=$(jq -r '.title // ""' <<<"${entry}")
  min_schema=$(jq -r '.min_schema // ""' <<<"${entry}")

  if [[ -z "${uid}" || "${uid}" == "null" ]]; then
    echo "Manifest entry is missing a uid" >&2
    STATUS=1
    continue
  fi

  if [[ -z "${output}" || "${output}" == "null" ]]; then
    echo "Manifest entry ${uid} is missing an output path" >&2
    STATUS=1
    continue
  fi

  if [[ "${output:0:1}" != "/" ]]; then
    output="${REPO_ROOT}/${output}"
  fi

  response=$(mktemp)
  if ! curl -fsSL \
      -H "Authorization: Bearer ${PERF_GRAFANA_API_KEY}" \
      "${BASE_URL}/api/dashboards/uid/${uid}" >"${response}"; then
    echo "Failed to download dashboard ${uid}" >&2
    rm -f "${response}"
    STATUS=1
    continue
  fi

  if ! jq -e '.dashboard' "${response}" >/dev/null; then
    echo "Response for ${uid} is missing dashboard payload" >&2
    rm -f "${response}"
    STATUS=1
    continue
  fi

  schema_version=$(jq -r '.dashboard.schemaVersion' "${response}")
  dashboard_version=$(jq -r '.dashboard.version' "${response}")
  remote_uid=$(jq -r '.dashboard.uid' "${response}")
  remote_title=$(jq -r '.dashboard.title // ""' "${response}")

  if [[ "${schema_version}" == "null" || ! "${schema_version}" =~ ^[0-9]+$ ]]; then
    echo "Dashboard ${uid} has invalid schemaVersion: ${schema_version}" >&2
    rm -f "${response}"
    STATUS=1
    continue
  fi

  if [[ "${dashboard_version}" == "null" || ! "${dashboard_version}" =~ ^[0-9]+$ ]]; then
    echo "Dashboard ${uid} has invalid version: ${dashboard_version}" >&2
    rm -f "${response}"
    STATUS=1
    continue
  fi

  if [[ "${remote_uid}" != "${uid}" ]]; then
    echo "Dashboard UID mismatch: expected ${uid}, got ${remote_uid}" >&2
    rm -f "${response}"
    STATUS=1
    continue
  fi

  if [[ -n "${min_schema}" && "${min_schema}" != "null" ]]; then
    if [[ ! "${min_schema}" =~ ^[0-9]+$ ]]; then
      echo "Manifest min_schema for ${uid} must be numeric" >&2
      rm -f "${response}"
      STATUS=1
      continue
    fi
    if (( schema_version < min_schema )); then
      echo "Dashboard ${uid} schemaVersion ${schema_version} is below minimum ${min_schema}" >&2
      rm -f "${response}"
      STATUS=1
      continue
    fi
  fi

  if [[ "${MODE}" == "write" ]]; then
    mkdir -p "$(dirname "${output}")"
    jq '.dashboard' "${response}" >"${output}"
    echo "Updated ${output}" >&2
    rm -f "${response}"
    continue
  fi

  if [[ ! -f "${output}" ]]; then
    echo "Dashboard export ${output} is missing" >&2
    rm -f "${response}"
    STATUS=1
    continue
  fi

  local_schema=$(jq -r '.schemaVersion' "${output}")
  local_version=$(jq -r '.version' "${output}")
  local_title=$(jq -r '.title // ""' "${output}")

  if [[ "${local_schema}" != "${schema_version}" ]]; then
    echo "schemaVersion drift for ${uid}: repo=${local_schema}, grafana=${schema_version}" >&2
    STATUS=1
  fi

  if [[ "${local_version}" != "${dashboard_version}" ]]; then
    echo "version drift for ${uid}: repo=${local_version}, grafana=${dashboard_version}" >&2
    STATUS=1
  fi

  if [[ -n "${title}" && "${title}" != "null" ]]; then
    if [[ "${local_title}" != "${title}" ]]; then
      echo "Title mismatch for ${uid}: expected '${title}', found '${local_title}'" >&2
      STATUS=1
    fi
    if [[ "${remote_title}" != "${title}" ]]; then
      echo "Grafana title mismatch for ${uid}: expected '${title}', found '${remote_title}'" >&2
      STATUS=1
    fi
  fi

  rm -f "${response}"
done < <(jq -c '.dashboards[]' "${MANIFEST}")

if [[ "${MODE}" == "verify" && ${STATUS} -eq 0 ]]; then
  echo "All dashboards are in sync." >&2
fi

exit ${STATUS}
