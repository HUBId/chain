#!/usr/bin/env bash
set -euo pipefail

rm -f /etc/paths.d/rpp-wallet
rm -rf /Applications/rpp-wallet-gui.app
/usr/bin/osascript -e 'tell application "System Events" to delete every login item whose name is "RPP Wallet"' >/dev/null 2>&1 || true
echo "Removed PATH entry and GUI bundle."
