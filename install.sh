#!/bin/bash
#
# Installs the privileged half of the nahime.firewall plugin:
#
#   /usr/local/lib/omarchy-firewall/omarchy-firewall   root:root 0755
#   /usr/share/polkit-1/actions/dev.nahime.firewall.policy   root:root 0644
#
# Run once, as root:  sudo ./install.sh
#
# The helper is COPIED, never symlinked. A symlink back into ~/.config would
# leave the program that pkexec runs as root writable by the user's session,
# which is the whole thing this layout exists to avoid. Re-run this script after
# pulling an update to the helper.
#
# Until this has been run the plugin still loads; it just stays read-only,
# because it will not run the user-writable copy of the helper under pkexec.

set -euo pipefail

SOURCE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
readonly SOURCE_DIR

HELPER_SRC="$SOURCE_DIR/bin/omarchy-firewall"
POLICY_SRC="$SOURCE_DIR/polkit/dev.nahime.firewall.policy"
HELPER_DIR=/usr/local/lib/omarchy-firewall
HELPER_DST="$HELPER_DIR/omarchy-firewall"
POLICY_DST=/usr/share/polkit-1/actions/dev.nahime.firewall.policy
readonly HELPER_SRC POLICY_SRC HELPER_DIR HELPER_DST POLICY_DST

die() {
  echo "install.sh: $*" >&2
  exit 1
}

(( EUID == 0 )) || die "run this as root: sudo $0"

[[ -f $HELPER_SRC ]] || die "helper not found at $HELPER_SRC"
[[ -f $POLICY_SRC ]] || die "polkit policy not found at $POLICY_SRC"
command -v ufw >/dev/null || die "ufw is not installed"

bash -n "$HELPER_SRC" || die "helper failed its syntax check; refusing to install it as root"

# The path pkexec is allowed to run is fixed by the policy's exec.path
# annotation. If the two ever disagree, every action fails with a confusing
# "not authorized" instead of anything that points at the mismatch.
grep -qF ">$HELPER_DST<" "$POLICY_SRC" ||
  die "the policy's exec.path does not name $HELPER_DST"

install -d -o root -g root -m 0755 "$HELPER_DIR"
install -o root -g root -m 0755 "$HELPER_SRC" "$HELPER_DST"
install -o root -g root -m 0644 "$POLICY_SRC" "$POLICY_DST"

# polkit picks new action files up on its own; this is only a readability check
# so a malformed policy is caught now rather than at the first password prompt.
if command -v xmllint >/dev/null; then
  xmllint --noout "$POLICY_DST" || die "installed policy is not valid XML"
fi

cat <<EOF

Installed:
  $HELPER_DST
  $POLICY_DST

The plugin can now change the firewall. Every change asks for your password
through the Omarchy polkit dialog (polkit action dev.nahime.firewall.manage,
auth_admin — nothing is cached between actions).

Add the widget to the bar with:
  omarchy plugin enable nahime.firewall --section right
EOF
