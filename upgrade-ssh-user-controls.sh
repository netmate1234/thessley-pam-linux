#!/usr/bin/env bash
# Safely deploy the per-user SSH controls to an existing Thessley PAM install.
# Does not edit sshd_config, /etc/pam.d, firewall rules, or GNOME login settings.
# Adds a narrow systemd ReadWritePaths allowance so the admin GUI can manage its DenyUsers fragment.
set -Eeuo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo "Run this script as root: sudo $0" >&2
    exit 1
fi

src=$(cd -- "$(dirname -- "$0")" && pwd)
lib=/usr/local/lib/thessley-pam
web_dropin_dir=/etc/systemd/system/thessley-pam-web.service.d
web_dropin=$web_dropin_dir/90-thessley-ssh-users.conf
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
if [[ -e "$web_dropin" ]]; then
    cp -a "$web_dropin" "$backup/web-ssh-dropin.conf"
    : > "$backup/web-ssh-dropin-present"
fi

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
        if [[ -e "$backup/web-ssh-dropin-present" ]]; then
            install -d -o root -g root -m 0755 "$web_dropin_dir"
            cp -a "$backup/web-ssh-dropin.conf" "$web_dropin" || true
        else
            rm -f -- "$web_dropin"
        fi
        systemctl daemon-reload || true
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
install -d -o root -g root -m 0755 "$web_dropin_dir"
cat > "$tmp/90-thessley-ssh-users.conf" <<'UNIT'
[Service]
ReadWritePaths=/etc/ssh/sshd_config.d
UNIT
install -o root -g root -m 0644 "$tmp/90-thessley-ssh-users.conf" "$web_dropin"
systemctl daemon-reload
web_writable_paths=$(systemctl show thessley-pam-web.service --property=ReadWritePaths --value)
if [[ " $web_writable_paths " != *" /etc/ssh/sshd_config.d "* ]]; then
    echo "The web service did not load the managed SSH policy write path." >&2
    exit 1
fi

for service in "${services[@]}"; do systemctl restart "$service"; done
echo "Per-user SSH controls installed. sshd_config, PAM login rules, firewall, and GNOME settings were not changed."
echo "The admin web service can now manage its own DenyUsers fragment."
echo "Backup: $backup"
for service in "${services[@]}"; do systemctl --no-pager --full status "$service" | sed -n '1,3p'; done
