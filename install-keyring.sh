#!/bin/sh
# Opt-in: let a phone login unlock the GNOME keyring. Installs the pieces; does NOT edit /etc/pam.d and does NOT
# seal anything. Run after install.sh.
#
#   sudo ./install-keyring.sh
#
# 1. /usr/local/lib/thessley-pam/thessley_pam/keyring.py and pam-keyring-helper   (root-owned, run as root)
# 2. pam_thessley_authtok.so, built here, into the system PAM module directory
#
# Then:  sudo thessley-pam keyring-link     (asks for your login password once and seals it in the TPM)
# and make sure /etc/pam.d/gdm-thessley has the three lines shown in packaging/gdm-thessley (install-login.sh
# installs that file). Undo: sudo ./uninstall-keyring.sh
set -eu

[ "$(id -u)" = 0 ] || { echo "Run with sudo." >&2; exit 1; }
[ -x /usr/local/lib/thessley-pam/pam-helper ] || { echo "Run install.sh first." >&2; exit 1; }
command -v gcc >/dev/null || { echo "Missing gcc: sudo apt install build-essential" >&2; exit 1; }
[ -f /usr/include/security/pam_modules.h ] || { echo "Missing PAM headers: sudo apt install libpam0g-dev" >&2; exit 1; }
command -v tpm2_unseal >/dev/null || { echo "Missing tpm2-tools: sudo apt install tpm2-tools" >&2; exit 1; }

src=$(cd "$(dirname "$0")" && pwd)
lib=/usr/local/lib/thessley-pam
secdir=$(dirname "$(find /lib /usr/lib -name pam_unix.so 2>/dev/null | head -n1)")
[ -d "$secdir" ] || { echo "Cannot find the PAM module directory." >&2; exit 1; }

install -o root -g root -m 0644 "$src/thessley_pam/keyring.py" "$lib/thessley_pam/keyring.py"
install -o root -g root -m 0755 "$src/pam-keyring-helper" "$lib/pam-keyring-helper"
# The keyring module only needs store.py and __init__.py, which install.sh already put there.

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
gcc -Wall -Wextra -Werror -O2 -fPIC -shared -o "$tmp/pam_thessley_authtok.so" "$src/pam-module/pam_thessley_authtok.c" -lpam
install -o root -g root -m 0644 "$tmp/pam_thessley_authtok.so" "$secdir/pam_thessley_authtok.so"

echo "Installed the helper in $lib and pam_thessley_authtok.so in $secdir."
echo "Next: sudo thessley-pam keyring-link"
