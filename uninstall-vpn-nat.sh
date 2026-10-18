#!/bin/sh
# Undo install-vpn-nat.sh: remove the NAT and forwarding rules and the unit.
set -eu
[ "$(id -u)" = 0 ] || { echo "Run with sudo." >&2; exit 1; }
systemctl disable --now thessley-pam-vpn-nat 2>/dev/null || true
rm -f /etc/systemd/system/thessley-pam-vpn-nat.service /usr/local/lib/thessley-pam/vpn-nat /etc/sysctl.d/99-thessley-vpn.conf
systemctl daemon-reload
echo "Removed the VPN NAT and forwarding rules."
