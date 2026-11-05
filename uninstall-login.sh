#!/bin/sh
# Undo install-login.sh: removes the QR login from the GNOME login and lock screens. Passwords are unaffected.
#
#   sudo ./uninstall-login.sh
set -eu

[ "$(id -u)" = 0 ] || { echo "Run with sudo." >&2; exit 1; }

uuid=thessley-passkey-login@eagleeye-intelligence.com
greeter=/etc/gdm3/greeter.dconf-defaults
gdm_password=/etc/pam.d/gdm-password

# Restore password fallback before removing the QR PAM service. Reverse only our marked rule, preserving any other
# administrator or package changes made to gdm-password since the feature was enabled. The helper keeps a root-only
# .bak-thessley-admin snapshot as an additional manual recovery point.
if [ -f "$gdm_password" ] && grep -q '^[[:space:]]*auth.*THESSLEY_QR_ONLY' "$gdm_password"; then
    python3 -I -c 'import sys; sys.path.insert(0, "/usr/local/lib/thessley-pam"); from thessley_pam import admin_helper; print(admin_helper.set_login_qr_only(False))'
fi

rm -f /etc/pam.d/gdm-thessley
rm -rf "/usr/share/gnome-shell/extensions/$uuid"
if [ -f "$greeter.bak-thessley" ]; then
    mv "$greeter.bak-thessley" "$greeter"
    /usr/share/gdm/generate-config
fi

echo "Removed. In your own session also run:  gnome-extensions disable $uuid"
