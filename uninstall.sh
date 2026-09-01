#!/bin/bash
#
# Removes the privileged half installed by install.sh. The plugin itself stays
# where it is and falls back to read-only.
#
# Run as root:  sudo ./uninstall.sh

set -euo pipefail

HELPER_DIR=/usr/local/lib/omarchy-firewall
POLICY_DST=/usr/share/polkit-1/actions/dev.nahime.firewall.policy
readonly HELPER_DIR POLICY_DST

(( EUID == 0 )) || { echo "uninstall.sh: run this as root: sudo $0" >&2; exit 1; }

rm -f "$POLICY_DST"
rm -f "$HELPER_DIR/omarchy-firewall"
rmdir --ignore-fail-on-non-empty "$HELPER_DIR" 2>/dev/null || true

echo "Removed the privileged helper and its polkit action."
echo "The plugin is now read-only. Remove it entirely with:"
echo "  omarchy plugin remove nahime.firewall"
