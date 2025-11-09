#!/bin/sh
set -euo pipefail

# Ensure positional parameters reflect the container invocation
set -- "$@"

if [ -n "${FIREWOOD_BENCH_DB_PATH:-}" ]; then
    db_path="${FIREWOOD_BENCH_DB_PATH}"
    db_dir="$(dirname "$db_path")"
    mkdir -p "$db_dir"
    set -- -d "$db_path" "$@"
fi

if [ -n "${FIREWOOD_BENCH_DURATION_MINUTES:-}" ]; then
    set -- -t "${FIREWOOD_BENCH_DURATION_MINUTES}" "$@"
fi

case "${FIREWOOD_BENCH_TELEMETRY:-}" in
    1|true|TRUE|True|yes|YES|on|ON)
        set -- -e "$@"
        ;;
    0|false|FALSE|False|no|NO|off|OFF|"")
        ;;
    *)
        echo "Warning: unrecognized FIREWOOD_BENCH_TELEMETRY value '${FIREWOOD_BENCH_TELEMETRY}'. Expected a boolean." >&2
        ;;
esac

exec /usr/local/bin/benchmark "$@"

