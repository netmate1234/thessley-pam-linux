#!/bin/sh
# Undo install-web.sh: stop and remove the admin web page service (keys and settings are kept).
set -eu
[ "$(id -u)" = 0 ] || { echo "Run with sudo." >&2; exit 1; }
systemctl disable --now thessley-pam-web 2>/dev/null || true
rm -f /etc/systemd/system/thessley-pam-web.service
systemctl daemon-reload
echo "Removed the thessley-pam-web service."
