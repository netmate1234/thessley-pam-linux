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

for name in ("web.py", "grants.py", "pam.py", "machine.py"):
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
if [[ -e /usr/local/sbin/thessley-ssh-config-rollback ]]; then
    cp -a /usr/local/sbin/thessley-ssh-config-rollback "$backup/ssh-config-rollback"
    : > "$backup/ssh-config-rollback-present"
fi
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
        rollback_failed=0
        cp -a "$backup/thessley_pam/." "$lib/thessley_pam/" || {
            echo "Rollback could not restore Python modules into $lib/thessley_pam" >&2
            rollback_failed=1
        }
        cp -a "$backup/pam_thessley_phone.so" "$old_module" || {
            echo "Rollback could not restore the SSH PAM module at $old_module" >&2
            rollback_failed=1
        }
        if [[ -e "$backup/ssh-config-rollback-present" ]]; then
            cp -a "$backup/ssh-config-rollback" /usr/local/sbin/thessley-ssh-config-rollback || {
                echo 'Rollback could not restore the SSH rollback helper.' >&2
                rollback_failed=1
            }
        else
            rm -f /usr/local/sbin/thessley-ssh-config-rollback || rollback_failed=1
        fi
        if [[ -e "$backup/web-ssh-dropin-present" ]]; then
            install -d -o root -g root -m 0755 "$web_dropin_dir" || {
                echo "Rollback could not recreate $web_dropin_dir" >&2
                rollback_failed=1
            }
            if [[ -d "$web_dropin_dir" ]]; then
                cp -a "$backup/web-ssh-dropin.conf" "$web_dropin" || {
                    echo "Rollback could not restore $web_dropin" >&2
                    rollback_failed=1
                }
            fi
        else
            rm -f -- "$web_dropin" || {
                echo "Rollback could not remove the partial SSH web-service override" >&2
                rollback_failed=1
            }
        fi
        systemctl daemon-reload || {
            echo 'Rollback could not reload systemd units.' >&2
            rollback_failed=1
        }
        for service in "${services[@]}"; do
            systemctl restart "$service" || {
                echo "Rollback could not restart $service" >&2
                rollback_failed=1
            }
        done
        if (( rollback_failed )); then
            echo "Rollback was incomplete. Keep this backup for recovery: $backup" >&2
        else
            echo "Rollback completed. Backup retained at $backup" >&2
        fi
    fi
    rm -rf -- "$tmp" || echo "Could not remove temporary staging directory: $tmp" >&2
    exit "$rc"
}
trap rollback EXIT

gcc -Wall -Wextra -Werror -O2 -fPIC -shared \
    -o "$tmp/pam_thessley_phone.so" "$src/pam-module/pam_thessley_phone.c" -lpam

applied=1
install -o root -g root -m 0644 "$src/thessley_pam/web.py" "$lib/thessley_pam/web.py"
install -o root -g root -m 0755 "$src/ssh-config-rollback.sh" /usr/local/sbin/thessley-ssh-config-rollback
install -o root -g root -m 0644 "$src/thessley_pam/grants.py" "$lib/thessley_pam/grants.py"
install -o root -g root -m 0644 "$src/thessley_pam/pam.py" "$lib/thessley_pam/pam.py"
install -o root -g root -m 0644 "$src/thessley_pam/machine.py" "$lib/thessley_pam/machine.py"
install -o root -g root -m 0644 "$tmp/pam_thessley_phone.so" "$old_module"
find "$lib/thessley_pam" -name __pycache__ -type d -prune -exec rm -rf -- {} +
install -d -o root -g root -m 0755 "$web_dropin_dir"
install -d -o root -g root -m 0700 /var/lib/thessley-ssh-config-rollback
cat > "$tmp/90-thessley-ssh-users.conf" <<'UNIT'
[Service]
ReadWritePaths=/etc/ssh/sshd_config.d /etc/systemd/system /var/lib/thessley-ssh-config-rollback /var/backups
UNIT
install -o root -g root -m 0644 "$tmp/90-thessley-ssh-users.conf" "$web_dropin"
systemctl daemon-reload
web_writable_paths=$(systemctl show thessley-pam-web.service --property=ReadWritePaths --value)
if [[ " $web_writable_paths " != *" /etc/ssh/sshd_config.d "* || " $web_writable_paths " != *" /etc/systemd/system "* || " $web_writable_paths " != *" /var/backups "* ]]; then
    echo "The web service did not load the managed SSH and rollback write paths." >&2
    exit 1
fi

for service in "${services[@]}"; do systemctl restart "$service"; done
echo "Per-user SSH controls installed. sshd_config, PAM login rules, firewall, and GNOME settings were not changed."
echo "The admin web service can manage SSH account policy and the timed SSH/PAM rollback."
echo "Backup: $backup"
for service in "${services[@]}"; do systemctl --no-pager --full status "$service" | sed -n '1,3p'; done
