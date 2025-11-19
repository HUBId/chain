#!/usr/bin/env bash
set -euo pipefail

BIN_ROOT="/usr/local/bin"
SERVICE="rpp-wallet-rpc.service"
SYSTEMD_DIR="/usr/lib/systemd/system"

rm -f "${BIN_ROOT}/rpp-wallet" "${BIN_ROOT}/rpp-wallet-gui"
rm -f "${SYSTEMD_DIR}/${SERVICE}"
if command -v systemctl >/dev/null 2>&1; then
  systemctl disable --now "${SERVICE}" >/dev/null 2>&1 || true
  systemctl daemon-reload
fi
printf 'Removed wallet binaries from %s and cleaned up %s/%s\n' "${BIN_ROOT}" "${SYSTEMD_DIR}" "${SERVICE}"
