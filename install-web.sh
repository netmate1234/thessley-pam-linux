#!/bin/sh
# Installs the Thessley admin web page as a systemd service (off until you switch it on):
#
#   sudo ./install-web.sh               once, after install.sh
#   sudo thessley-pam web on            start it (and at every boot);  web off  stops it
#   sudo thessley-pam web status        the address and the certificate's fingerprint
#
# By default it listens on this computer's LAN address, port 47820, over HTTPS with a certificate of its own (a browser
# warns once; "thessley-pam web cert CERT KEY" gives it a real one). Settings: thessley-pam web listen|port|session.
# Open port 47820 in a firewall only for networks you trust. Undo: sudo ./uninstall-web.sh
set -eu

[ "$(id -u)" = 0 ] || { echo "Run with sudo." >&2; exit 1; }
[ -x /usr/local/sbin/thessley-pam ] || { echo "Run install.sh first." >&2; exit 1; }
src=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
[ -x "$src/prepare-enrolled-list.sh" ] || { echo "Missing prepare-enrolled-list.sh from the Thessley source package." >&2; exit 1; }
command -v qrencode >/dev/null || { echo "Missing qrencode: sudo apt install qrencode" >&2; exit 1; }
"$src/prepare-enrolled-list.sh"

unit=/etc/systemd/system/thessley-pam-web.service
cat > "$unit" <<'UNIT'
[Unit]
Description=Thessley admin web page (sign in with a phone approval, manage your keys)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/sbin/thessley-pam web serve
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
ProtectHome=yes
PrivateTmp=yes
ProtectSystem=full
# The web UI issues client certificates; allow EasyRSA to update its PKI, but keep the CA signing key read-only.
ReadWritePaths=/etc/thessley-pam /etc/ssh/sshd_config.d /etc/systemd/system /var/lib/thessley-pam /var/lib/thessley-ssh-config-rollback /var/backups -/etc/openvpn/easy-rsa-thessley/pki
ReadOnlyPaths=-/etc/openvpn/easy-rsa-thessley/pki/private/ca.key

[Install]
WantedBy=multi-user.target
UNIT
chmod 0644 "$unit"
systemctl daemon-reload
echo "Installed $unit (not started)."
echo "Start it with:  sudo thessley-pam web on"
