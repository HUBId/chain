#!/usr/bin/env bash
set -euo pipefail

PAYLOAD_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PATHS_DIR="/etc/paths.d"
ENTRY="rpp-wallet"
CLI_PATH="/usr/local/bin/rpp-wallet"
GUI_APP="/Applications/rpp-wallet-gui.app"

install -d -m 0755 "${PATHS_DIR}"
printf '%s\n' "${CLI_PATH%/*}" >"${PATHS_DIR}/${ENTRY}"
cat <<MSG
RPP Wallet CLI available on PATH after new shell sessions.
To install the GUI manually, copy rpp-wallet-gui.app into /Applications
and re-run this script. The pkg installer handles this automatically.
MSG
