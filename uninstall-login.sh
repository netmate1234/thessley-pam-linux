#!/bin/sh
# Undo install-login.sh: removes the QR login from the GNOME login and lock screens. Passwords are unaffected.
#
#   sudo ./uninstall-login.sh
set -eu

[ "$(id -u)" = 0 ] || { echo "Run with sudo." >&2; exit 1; }

uuid=thessley-passkey-login@eagleeye-intelligence.com
greeter=/etc/gdm3/greeter.dconf-defaults

rm -f /etc/pam.d/gdm-thessley
rm -rf "/usr/share/gnome-shell/extensions/$uuid"
if [ -f "$greeter.bak-thessley" ]; then
    mv "$greeter.bak-thessley" "$greeter"
    /usr/share/gdm/generate-config
fi

echo "Removed. In your own session also run:  gnome-extensions disable $uuid"
