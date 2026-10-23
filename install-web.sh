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
command -v qrencode >/dev/null || { echo "Missing qrencode: sudo apt install qrencode" >&2; exit 1; }

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
ReadWritePaths=/etc/thessley-pam /etc/thessley-pam-enrolled -/etc/openvpn/easy-rsa-thessley/pki
ReadOnlyPaths=-/etc/openvpn/easy-rsa-thessley/pki/private/ca.key

[Install]
WantedBy=multi-user.target
UNIT
chmod 0644 "$unit"
# The unit may write this one file (the login-screen list); it has to exist for the sandbox to map it.
[ -e /etc/thessley-pam-enrolled ] || install -m 0644 /dev/null /etc/thessley-pam-enrolled
systemctl daemon-reload
echo "Installed $unit (not started)."
echo "Start it with:  sudo thessley-pam web on"
