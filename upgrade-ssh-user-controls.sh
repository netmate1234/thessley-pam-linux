#!/usr/bin/env bash
# Safely deploy the per-user SSH controls to an existing Thessley PAM install.
# Does not edit sshd_config, /etc/pam.d, firewall rules, or GNOME login settings.
set -Eeuo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo "Run this script as root: sudo $0" >&2
    exit 1
fi

src=$(cd -- "$(dirname -- "$0")" && pwd)
lib=/usr/local/lib/thessley-pam
[[ -d "$lib/thessley_pam" ]] || { echo "Thessley PAM is not installed at $lib" >&2; exit 1; }
for file in web.py grants.py pam.py; do
    [[ -f "$src/thessley_pam/$file" ]] || { echo "Missing source: $src/thessley_pam/$file" >&2; exit 1; }
done
[[ -f "$src/pam-module/pam_thessley_phone.c" ]] || { echo "Missing PAM module source." >&2; exit 1; }
command -v gcc >/dev/null || { echo "gcc is required (install build-essential first)." >&2; exit 1; }
[[ -f /usr/include/security/pam_modules.h ]] || { echo "PAM headers are required (install libpam0g-dev first)." >&2; exit 1; }

python3 - "$src/thessley_pam" <<'PY'
import ast
import pathlib
import sys

for name in ("web.py", "grants.py", "pam.py"):
    path = pathlib.Path(sys.argv[1]) / name
    ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
PY

pam_unix=$(find /lib /usr/lib -name pam_unix.so -print -quit 2>/dev/null || true)
[[ -n "$pam_unix" ]] || { echo "Cannot find the system PAM module directory." >&2; exit 1; }
secdir=$(dirname -- "$pam_unix")
old_module=$secdir/pam_thessley_phone.so
[[ -f "$old_module" ]] || { echo "Installed Thessley SSH PAM module not found at $old_module" >&2; exit 1; }

tmp=$(mktemp -d /tmp/thessley-ssh-upgrade.XXXXXX)
backup=/var/backups/thessley-pam-upgrade-$(date +%Y%m%d-%H%M%S)
install -d -o root -g root -m 0700 "$backup"
cp -a "$lib/thessley_pam" "$backup/thessley_pam"
cp -a "$old_module" "$backup/pam_thessley_phone.so"
printf '%s\n' "$lib/thessley_pam" "$old_module" > "$backup/restore-paths.txt"

services=()
for service in thessley-pam-approvals.service thessley-pam-web.service; do
    if systemctl is-active --quiet "$service"; then
        services+=("$service")
    fi
done

applied=0
rollback() {
    rc=$?
    if (( rc != 0 && applied )); then
        echo "Upgrade failed; restoring the previous files from $backup" >&2
        cp -a "$backup/thessley_pam/." "$lib/thessley_pam/" || true
        cp -a "$backup/pam_thessley_phone.so" "$old_module" || true
        for service in "${services[@]}"; do systemctl restart "$service" || true; done
        echo "Rollback attempted. Backup retained at $backup" >&2
    fi
    rm -rf -- "$tmp"
    exit "$rc"
}
trap rollback EXIT

gcc -Wall -Wextra -Werror -O2 -fPIC -shared \
    -o "$tmp/pam_thessley_phone.so" "$src/pam-module/pam_thessley_phone.c" -lpam

applied=1
install -o root -g root -m 0644 "$src/thessley_pam/web.py" "$lib/thessley_pam/web.py"
install -o root -g root -m 0644 "$src/thessley_pam/grants.py" "$lib/thessley_pam/grants.py"
install -o root -g root -m 0644 "$src/thessley_pam/pam.py" "$lib/thessley_pam/pam.py"
install -o root -g root -m 0644 "$tmp/pam_thessley_phone.so" "$old_module"
find "$lib/thessley_pam" -name __pycache__ -type d -prune -exec rm -rf -- {} +

for service in "${services[@]}"; do systemctl restart "$service"; done
echo "Per-user SSH controls installed. Existing SSH/PAM/GNOME configuration was not changed."
echo "Backup: $backup"
for service in "${services[@]}"; do systemctl --no-pager --full status "$service" | sed -n '1,3p'; done
