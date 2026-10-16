#!/bin/sh
# Install the Thessley Login admin window (a menu entry called "Thessley Login"). Run after install.sh.
#
#   sudo ./install-admin.sh
#
# Installs only: the window, its root helper, a polkit action that lets the helper run after one administrator
# password, a menu entry, and the current cli.py / keyring.py / store.py / pam.py (disabled phones are honoured by pam.py;
# the window opens `thessley-pam enroll` and
# `keyring-link` in a terminal). It does not touch /etc/pam.d. Undo: sudo ./uninstall-admin.sh
set -eu

[ "$(id -u)" = 0 ] || { echo "Run with sudo." >&2; exit 1; }
[ -x /usr/local/lib/thessley-pam/pam-helper ] || { echo "Run install.sh first." >&2; exit 1; }
python3 -c 'import gi; gi.require_version("Adw", "1"); from gi.repository import Adw' 2>/dev/null \
    || { echo "Missing GTK 4 / libadwaita for Python: sudo apt install python3-gi gir1.2-adw-1" >&2; exit 1; }
command -v pkexec >/dev/null || { echo "Missing pkexec: sudo apt install policykit-1" >&2; exit 1; }

src=$(cd "$(dirname "$0")" && pwd)
lib=/usr/local/lib/thessley-pam

for f in admin_helper.py admin_gui.py keyring.py cli.py store.py pam.py; do
    install -o root -g root -m 0644 "$src/thessley_pam/$f" "$lib/thessley_pam/$f"
done
install -o root -g root -m 0755 "$src/admin-helper" "$lib/admin-helper"
install -o root -g root -m 0755 "$src/thessley-pam-admin" /usr/local/bin/thessley-pam-admin
install -o root -g root -m 0644 "$src/packaging/org.thessley.pam.policy" /usr/share/polkit-1/actions/org.thessley.pam.policy
install -o root -g root -m 0644 "$src/packaging/thessley-pam-admin.desktop" /usr/share/applications/thessley-pam-admin.desktop
command -v update-desktop-database >/dev/null && update-desktop-database /usr/share/applications 2>/dev/null || true
find "$lib" -name __pycache__ -prune -exec rm -rf {} +

echo "Installed. Open \"Thessley Login\" from the applications menu, or run thessley-pam-admin."
