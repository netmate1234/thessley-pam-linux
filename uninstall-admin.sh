#!/bin/sh
# Remove the admin window. Leaves cli.py / keyring.py in place (the login itself uses them).
set -eu
[ "$(id -u)" = 0 ] || { echo "Run with sudo." >&2; exit 1; }
rm -f /usr/local/bin/thessley-pam-admin /usr/share/polkit-1/actions/org.thessley.pam.policy \
      /usr/share/applications/thessley-pam-admin.desktop /usr/local/lib/thessley-pam/admin-helper \
      /usr/local/lib/thessley-pam/thessley_pam/admin_helper.py /usr/local/lib/thessley-pam/thessley_pam/admin_gui.py
command -v update-desktop-database >/dev/null && update-desktop-database /usr/share/applications 2>/dev/null || true
echo "Removed."
