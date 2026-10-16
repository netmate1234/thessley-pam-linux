#!/bin/sh
# Remove what install-keyring.sh installed, and every sealed password. Edit /etc/pam.d/gdm-thessley (or
# re-run uninstall-login.sh) to drop the pam_thessley_authtok.so line; a missing module is ignored there.
set -eu
[ "$(id -u)" = 0 ] || { echo "Run with sudo." >&2; exit 1; }
secdir=$(dirname "$(find /lib /usr/lib -name pam_unix.so 2>/dev/null | head -n1)")
rm -f "$secdir/pam_thessley_authtok.so" /usr/local/lib/thessley-pam/pam-keyring-helper /usr/local/lib/thessley-pam/thessley_pam/keyring.py
rm -rf /etc/thessley-pam/keyring
echo "Removed."
