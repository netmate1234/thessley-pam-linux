#!/usr/bin/env bash
# Install thessley-pam into root-owned locations. Does NOT change /etc/pam.d.
# A timestamped backup is created before any installed file is changed. If the
# approval service cannot be activated, installed code and unit state roll back.
set -Eeuo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo "Run with sudo: sudo bash $0" >&2
    exit 1
fi

command -v qrencode >/dev/null || { echo "Missing qrencode: sudo apt install qrencode" >&2; exit 1; }
python3 -c 'import cryptography' 2>/dev/null || { echo "Missing python3-cryptography" >&2; exit 1; }
python3 -c 'import asn1crypto' 2>/dev/null || { echo "Missing python3-asn1crypto (TPM certificate support): sudo apt install python3-asn1crypto" >&2; exit 1; }
command -v systemctl >/dev/null || { echo "systemd is required by this installer." >&2; exit 1; }

# Clock comparison is diagnostic only. Do not let a single web server's Date
# header block installation or imply that the local clock is necessarily wrong.
python3 - <<'PY'
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.request import Request, urlopen

url = "https://wp-opsec.eagleeye-intelligence.com/"
try:
    request = Request(url, method="HEAD", headers={"Cache-Control": "no-cache"})
    with urlopen(request, timeout=8) as response:
        header = response.headers.get("Date")
    if not header:
        raise RuntimeError("the HTTPS server returned no Date header")
    reference = parsedate_to_datetime(header).astimezone(timezone.utc)
    local = datetime.now(timezone.utc)
    delta = round((local - reference).total_seconds())
    print(
        "Clock diagnostic (informational): system UTC "
        f"{local:%Y-%m-%d %H:%M:%S}; reference HTTP Date UTC "
        f"{reference:%Y-%m-%d %H:%M:%S}; difference {delta}s."
    )
    if abs(delta) > 60:
        print(
            "WARNING: continuing installation. This comparison cannot tell which clock is inaccurate; "
            "time-zone settings are not part of it."
        )
except Exception as exc:
    print(f"WARNING: clock comparison unavailable ({exc}); continuing installation.")
PY

src=$(cd -- "$(dirname -- "$0")" && pwd)
lib=/usr/local/lib/thessley-pam
bin=/usr/local/sbin/thessley-pam
helper=/usr/local/lib/thessley-pam/pam-helper
unit=/etc/systemd/system/thessley-pam-approvals.service

[[ -d "$src/thessley_pam" ]] || { echo "Missing source package: $src/thessley_pam" >&2; exit 1; }
[[ -f "$src/pam-helper" && -f "$src/thessley-pam" ]] || { echo "Missing PAM helper or CLI source." >&2; exit 1; }
python3 - "$src/thessley_pam" <<'PY'
import ast
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
for path in sorted(root.glob("*.py")):
    ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
PY

tmp=$(mktemp -d /tmp/thessley-pam-install.XXXXXX)
backup=$(mktemp -d "/var/backups/thessley-pam-install-$(date +%Y%m%d-%H%M%S).XXXXXX")
chown root:root "$backup"
chmod 0700 "$backup"
install -d -o root -g root -m 0700 "$tmp/stage"

# Stage a complete tree and validate its contents before touching the install.
install -d -o root -g root -m 0755 "$tmp/stage/lib/thessley_pam" "$tmp/stage/lib/thessley_pam/tpm_roots"
install -o root -g root -m 0644 "$src"/thessley_pam/*.py "$tmp/stage/lib/thessley_pam/"
for f in "$src"/thessley_pam/tpm_roots/*.pem; do
    [[ -f "$f" ]] && install -o root -g root -m 0644 "$f" "$tmp/stage/lib/thessley_pam/tpm_roots/"
done
if [[ -f "$src/thessley_pam/logo.png" ]]; then
    install -o root -g root -m 0644 "$src/thessley_pam/logo.png" "$tmp/stage/lib/thessley_pam/"
fi
install -o root -g root -m 0755 "$src/pam-helper" "$tmp/stage/lib/pam-helper"
install -o root -g root -m 0755 "$src/thessley-pam" "$tmp/stage/thessley-pam"
PYTHONPATH="$tmp/stage/lib" python3 -I -c "import ast,pathlib; p=pathlib.Path('$tmp/stage/lib/thessley_pam'); [ast.parse(x.read_text(encoding='utf-8')) for x in p.glob('*.py')]"

# Capture exact prior state, including absence, so a first install can roll back too.
for path in "$lib" "$bin" "$unit"; do
    key=$(printf '%s' "$path" | sed 's#^/##; s#/#__#g')
    if [[ -e "$path" || -L "$path" ]]; then
        cp -a --parents "$path" "$backup/"
        printf '%s\n' present > "$backup/$key.state"
    else
        printf '%s\n' absent > "$backup/$key.state"
    fi
done
systemctl is-enabled --quiet thessley-pam-approvals.service && printf 'enabled\n' > "$backup/service-enabled.state" || printf 'disabled\n' > "$backup/service-enabled.state"
systemctl is-active --quiet thessley-pam-approvals.service && printf 'active\n' > "$backup/service-active.state" || printf 'inactive\n' > "$backup/service-active.state"

applied=0
rollback() {
    rc=$?
    if (( rc != 0 && applied )); then
        trap - ERR EXIT
        echo "Install/activation failed; restoring previous installed files." >&2
        for path in "$lib" "$bin" "$unit"; do
            key=$(printf '%s' "$path" | sed 's#^/##; s#/#__#g')
            rm -rf -- "$path"
            if [[ $(cat "$backup/$key.state") == present ]]; then
                install -d -o root -g root -m 0755 "$(dirname -- "$path")"
                cp -a "$backup/${path#/}" "$path"
            fi
        done
        systemctl daemon-reload || true
        if [[ $(cat "$backup/service-enabled.state") == enabled ]]; then
            systemctl enable thessley-pam-approvals.service || true
        else
            systemctl disable thessley-pam-approvals.service || true
        fi
        if [[ $(cat "$backup/service-active.state") == active ]]; then
            systemctl restart thessley-pam-approvals.service || true
        else
            systemctl stop thessley-pam-approvals.service || true
        fi
        echo "Rollback attempted. Backup retained at $backup" >&2
    fi
    rm -rf -- "$tmp"
    exit "$rc"
}
trap rollback EXIT

applied=1
install -d -o root -g root -m 0755 "$lib" "$lib/thessley_pam"
cp -a "$tmp/stage/lib/thessley_pam/." "$lib/thessley_pam/"
install -o root -g root -m 0755 "$tmp/stage/lib/pam-helper" "$helper"
install -o root -g root -m 0755 "$tmp/stage/thessley-pam" "$bin"
find "$lib" -name __pycache__ -type d -prune -exec rm -rf -- {} +

cat > "$tmp/thessley-pam-approvals.service" <<'UNIT'
[Unit]
Description=Thessley shared HTTPS listener for SSH and local phone approvals (VPN uses port 47830)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/sbin/thessley-pam approvals serve
Restart=on-failure
RestartSec=5
RuntimeDirectory=thessley-pam
RuntimeDirectoryMode=0750
RuntimeDirectoryPreserve=yes
# OpenVPN's auth hook runs as nobody:nogroup and connects to vpn.sock here.
Group=nogroup
ExecStartPre=/usr/bin/chown root:nogroup /run/thessley-pam
ExecStartPre=/usr/bin/chmod 0750 /run/thessley-pam
NoNewPrivileges=yes
ProtectHome=yes
PrivateTmp=yes
ProtectSystem=full
ReadWritePaths=/etc/thessley-pam /run/thessley-pam

[Install]
WantedBy=multi-user.target
UNIT
install -o root -g root -m 0644 "$tmp/thessley-pam-approvals.service" "$unit"
systemctl daemon-reload
systemctl enable thessley-pam-approvals.service
systemctl restart thessley-pam-approvals.service

# Require both service health and the expected listener socket before success.
systemctl is-active --quiet thessley-pam-approvals.service
for _ in {1..10}; do
    if ss -H -ltn '( sport = :47810 )' | grep -q .; then break; fi
    sleep 1
done
ss -H -ltn '( sport = :47810 )' | grep -q . || { echo "Approval service did not listen on TCP 47810." >&2; exit 1; }

trap - EXIT
rm -rf -- "$tmp"
echo "Installed and health-checked Thessley PAM in $lib and $bin."
echo "Backup: $backup"
echo "The installer did not edit /etc/pam.d or SSH policy."
