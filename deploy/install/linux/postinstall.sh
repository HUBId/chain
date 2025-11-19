#!/usr/bin/env bash
set -euo pipefail

PAYLOAD_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_ROOT="/usr/local/bin"
CONFIG_ROOT="/etc/rpp-wallet"
SYSTEMD_DIR="/usr/lib/systemd/system"
SERVICE="rpp-wallet-rpc.service"

install -d -m 0755 "${BIN_ROOT}" "${CONFIG_ROOT}" "${SYSTEMD_DIR}" /var/lib/rpp-wallet /var/log/rpp-wallet
install -m 0755 "${PAYLOAD_ROOT}/bin/rpp-wallet" "${BIN_ROOT}/rpp-wallet"
install -m 0755 "${PAYLOAD_ROOT}/bin/rpp-wallet-gui" "${BIN_ROOT}/rpp-wallet-gui"
for cfg in "${PAYLOAD_ROOT}"/config/*.toml; do
  install -m 0640 "$cfg" "${CONFIG_ROOT}/$(basename "$cfg")"
done
install -m 0644 "${PAYLOAD_ROOT}/systemd/${SERVICE}" "${SYSTEMD_DIR}/${SERVICE}"
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
  systemctl enable "${SERVICE}" >/dev/null 2>&1 || true
fi
printf '\nInstalled rpp-wallet binaries into %s and configs into %s\n' "${BIN_ROOT}" "${CONFIG_ROOT}"
printf 'Systemd unit is available as %s/%s\n' "${SYSTEMD_DIR}" "${SERVICE}"
printf 'Logs: /var/log/rpp-wallet (ensure permissions allow wallet user access).\n'
