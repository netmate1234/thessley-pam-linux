#!/bin/sh
# Opt-in: QR-code login on the GNOME login and lock screens (password keeps working). Run after install.sh.
#
#   sudo ./install-login.sh
#
# 1. /etc/pam.d/gdm-thessley       phone-only PAM service, used only by the extension
# 2. GNOME Shell extension         system-wide, in /usr/share/gnome-shell/extensions
# 3. login screen                  enables the extension for the gdm user (/etc/gdm3/greeter.dconf-defaults)
#
# Takes effect on the login screen after the next log-out or reboot; for the lock screen, enable it in your
# own session too (printed at the end). Undo everything with: sudo ./uninstall-login.sh
set -eu

[ "$(id -u)" = 0 ] || { echo "Run with sudo." >&2; exit 1; }
[ -x /usr/local/lib/thessley-pam/pam-helper ] || { echo "Run install.sh first." >&2; exit 1; }

src=$(cd "$(dirname "$0")" && pwd)
"$src/prepare-enrolled-list.sh"
uuid=thessley-passkey-login@eagleeye-intelligence.com
ext=/usr/share/gnome-shell/extensions/$uuid
greeter=/etc/gdm3/greeter.dconf-defaults

install -o root -g root -m 0644 "$src/packaging/gdm-thessley" /etc/pam.d/gdm-thessley

# The extension reads /var/lib/thessley-pam/enrolled-users to know whom to offer the QR code; (re)write it now for
# phones enrolled before this was installed.
python3 -I -c 'import sys; sys.path.insert(0, "/usr/local/lib/thessley-pam")
from thessley_pam import store
store.ensure_dirs()
store.write_enrolled_list()'

install -d -o root -g root -m 0755 "$ext"
for f in metadata.json extension.js stylesheet.css; do
    install -o root -g root -m 0644 "$src/gnome-extension/$uuid/$f" "$ext/$f"
done
install -o root -g root -m 0644 "$src/thessley_pam/logo.png" "$ext/logo.png"

if ! grep -q "$uuid" "$greeter"; then
    cp -a "$greeter" "$greeter.bak-thessley"
    if grep -q '^\[org/gnome/shell\]' "$greeter"; then
        echo "$greeter already has an [org/gnome/shell] section; add $uuid to its enabled-extensions by hand." >&2
        exit 1
    fi
    printf '\n# Thessley Passkey: QR login on the login screen (install-login.sh)\n[org/gnome/shell]\nenabled-extensions=['"'"'%s'"'"']\n' "$uuid" >> "$greeter"
fi
/usr/share/gdm/generate-config

echo "Installed. The login screen picks it up after the next log-out or reboot."
echo "For the lock screen, run as yourself (not root):  gnome-extensions enable $uuid"
