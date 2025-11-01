# shellcheck shell=bash

rpp_has_flag() {
  local needle="$1"
  shift || true
  for arg in "$@"; do
    case "$arg" in
      "$needle"|"$needle="*)
        return 0
        ;;
    esac
  done
  return 1
}

rpp_assert_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: required command '$1' not found" >&2
    exit 127
  fi
}

rpp_init_health_headers() {
  if declare -p RPP_NODE_HEALTH_CURL_ARGS >/dev/null 2>&1; then
    return 0
  fi

  if [[ -z "${RPP_NODE_RPC_AUTH_TOKEN:-}" && -z "${RPP_NODE_HEALTH_HEADERS:-}" ]]; then
    return 0
  fi

  RPP_NODE_HEALTH_CURL_ARGS=()

  if [[ -n "${RPP_NODE_RPC_AUTH_TOKEN:-}" ]]; then
    RPP_NODE_HEALTH_CURL_ARGS+=("-H" "Authorization: Bearer ${RPP_NODE_RPC_AUTH_TOKEN}")
  fi

  if [[ -n "${RPP_NODE_HEALTH_HEADERS:-}" ]]; then
    while IFS= read -r header; do
      [[ -z "${header}" ]] && continue
      RPP_NODE_HEALTH_CURL_ARGS+=("-H" "${header}")
    done <<< "${RPP_NODE_HEALTH_HEADERS}"
  fi
}

rpp_wait_for_endpoint() {
  local pid="$1"
  local url="$2"
  local timeout="$3"
  local elapsed=0
  local -a curl_args=()

  rpp_init_health_headers

  if declare -p RPP_NODE_HEALTH_CURL_ARGS >/dev/null 2>&1; then
    curl_args=("${RPP_NODE_HEALTH_CURL_ARGS[@]}")
  fi

  while (( elapsed < timeout )); do
    if ! kill -0 "$pid" 2>/dev/null; then
      wait "$pid"
      exit $?
    fi
    if curl "${curl_args[@]}" --fail --silent --show-error --max-time 5 "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  echo "error: health check timed out for $url" >&2
  kill -TERM "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  exit 1
}

rpp_check_endpoints() {
  local pid="$1"
  local timeout="$2"
  shift 2
  local endpoint
  for endpoint in "$@"; do
    echo "checking $endpoint"
    rpp_wait_for_endpoint "$pid" "$endpoint" "$timeout"
  done
}

rpp_handle_signal() {
  local signal="$1"
  local pid="${RPP_NODE_CHILD_PID:-}"
  echo "signal $signal received, shutting down..." >&2
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    kill -"$signal" "$pid" 2>/dev/null || true
    wait "$pid"
    exit $?
  fi
  exit 0
}
