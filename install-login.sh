#!/bin/sh
# Opt-in: QR-code login on the GNOME login and lock screens (password fallback is configurable). Run after install.sh.
#
#   sudo ./install-login.sh
#
# 1. /etc/pam.d/gdm-thessley       phone-only PAM service, used only by the extension
# 2. GNOME Shell extension         system-wide, in /usr/share/gnome-shell/extensions
# 3. login screen                  enables the extension in GDM's active dconf source
#
# Takes effect on the login screen after the next log-out or reboot; for the lock screen, enable it in your
# own session too (printed at the end). A timed rollback is armed until the boot-time QR test is approved.
# sudo ./uninstall-login.sh
set -eu

[ "$(id -u)" = 0 ] || { echo "Run with sudo." >&2; exit 1; }
[ -x /usr/local/lib/thessley-pam/pam-helper ] || { echo "Run install.sh first." >&2; exit 1; }

src=$(cd "$(dirname "$0")" && pwd)
uuid=thessley-passkey-login@eagleeye-intelligence.com
ext=/usr/share/gnome-shell/extensions/$uuid
legacy_greeter=/etc/gdm3/greeter.dconf-defaults
gdm_dconf=/usr/share/gdm/dconf
gdm_settings=$gdm_dconf/99-thessley-passkey-login
rollback_helper=/usr/local/sbin/thessley-login-rollback

rollback_dir=$(bash "$src/login-rollback.sh" snapshot)
install -o root -g root -m 0755 "$src/login-rollback.sh" "$rollback_helper"
install_complete=no
rollback_on_error() {
    rc=$?
    trap - EXIT
    if [ "$rc" -ne 0 ] && [ "$install_complete" != yes ]; then
        echo "Installation failed; restoring the pre-install snapshot." >&2
        "$rollback_helper" restore "$rollback_dir" || echo "Automatic restore failed; snapshot retained at $rollback_dir" >&2
    fi
    exit "$rc"
}
trap rollback_on_error EXIT

"$src/prepare-enrolled-list.sh"

# Keep the shared approval command aware of the login rollback timer too.
install -o root -g root -m 0755 "$src/setup-rollback.sh" /usr/local/sbin/thessley-install-rollback
if [ -x /usr/local/bin/thessley-pam-admin ]; then
    install -o root -g root -m 0644 "$src/thessley_pam/admin_helper.py" /usr/local/lib/thessley-pam/thessley_pam/admin_helper.py
    install -o root -g root -m 0644 "$src/thessley_pam/admin_gui.py" /usr/local/lib/thessley-pam/thessley_pam/admin_gui.py
fi

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

if [ -d "$gdm_dconf" ]; then
    greeter=$gdm_settings
    if [ -e "$greeter" ] && ! grep -q "$uuid" "$greeter"; then
        echo "$greeter already exists and is not a Thessley setting; refusing to overwrite it." >&2
        exit 1
    fi
    if [ ! -e "$greeter" ]; then
        tmp=$(mktemp "$gdm_dconf/.thessley-passkey-login.XXXXXX")
        printf '# Thessley Passkey: QR login on the GDM greeter (install-login.sh)\n[org/gnome/shell]\nenabled-extensions=['"'"'%s'"'"']\n' "$uuid" > "$tmp"
        install -o root -g root -m 0644 "$tmp" "$greeter"
        rm -f "$tmp"
    fi
else
    greeter=$legacy_greeter
    if ! grep -q "$uuid" "$greeter"; then
        cp -a "$greeter" "$greeter.bak-thessley"
        if grep -q '^\[org/gnome/shell\]' "$greeter"; then
            echo "$greeter already has an [org/gnome/shell] section; add $uuid to its enabled-extensions by hand." >&2
            exit 1
        fi
        printf '\n# Thessley Passkey: QR login on the login screen (install-login.sh)\n[org/gnome/shell]\nenabled-extensions=['"'"'%s'"'"']\n' "$uuid" >> "$greeter"
    fi
fi
/usr/share/gdm/generate-config
"$rollback_helper" arm "$rollback_dir" 20
install_complete=yes

echo "Installed. The login screen picks it up after the next log-out or reboot."
echo "For the lock screen, run as yourself (not root):  gnome-extensions enable $uuid"
echo "Rollback snapshot: $rollback_dir"
echo "A 20-minute rollback repeats its countdown after reboot. Test the cold-boot QR and approve in Admin or run: sudo thessley-install-rollback approve"
echo "To remove the integration later: sudo ./uninstall-login.sh"
