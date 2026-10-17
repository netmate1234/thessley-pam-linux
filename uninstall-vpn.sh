#!/bin/sh
# Undo install-vpn.sh: stop and remove the VPN approval service (keys and settings are kept). OpenVPN's own config still
# names the vpn-auth script, so remove its auth-user-pass-verify line first, or logins are refused.
set -eu
[ "$(id -u)" = 0 ] || { echo "Run with sudo." >&2; exit 1; }
systemctl disable --now thessley-pam-vpn 2>/dev/null || true
rm -f /etc/systemd/system/thessley-pam-vpn.service /usr/local/lib/thessley-pam/vpn-auth
systemctl daemon-reload
echo "Removed the thessley-pam-vpn service."
