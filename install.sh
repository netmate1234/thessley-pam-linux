#!/bin/sh
# Install thessley-pam into root-owned locations. Does NOT change /etc/pam.d; see README for that step.
#
#   sudo ./install.sh
#
# The PAM helper runs as root, so it and the code it imports must not be writable by anyone but root:
# never point /etc/pam.d at a copy inside a home directory.
set -eu

[ "$(id -u)" = 0 ] || { echo "Run with sudo." >&2; exit 1; }
command -v qrencode >/dev/null || { echo "Missing qrencode: sudo apt install qrencode" >&2; exit 1; }
python3 -c 'import cryptography' 2>/dev/null || { echo "Missing python3-cryptography" >&2; exit 1; }

src=$(cd "$(dirname "$0")" && pwd)
lib=/usr/local/lib/thessley-pam

install -d -o root -g root -m 0755 "$lib" "$lib/thessley_pam"
for f in "$src"/thessley_pam/*.py; do
    install -o root -g root -m 0644 "$f" "$lib/thessley_pam/"
done
install -o root -g root -m 0755 "$src/pam-helper" "$lib/pam-helper"
install -o root -g root -m 0755 "$src/thessley-pam" /usr/local/sbin/thessley-pam
find "$lib" -name __pycache__ -prune -exec rm -rf {} +

echo "Installed to $lib and /usr/local/sbin/thessley-pam"
