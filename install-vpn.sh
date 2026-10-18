#!/bin/sh
# Installs the Thessley approval for OpenVPN as a systemd service (off until you switch it on):
#
#   sudo ./install-vpn.sh
#   sudo thessley-pam vpn public-host vpn.example.org     the name or address the device is told to connect to
#   sudo thessley-pam vpn on                               start it (and at every boot)
#
# It does NOT install or configure OpenVPN itself: docs/VPN.md has the server and client files. It installs:
#   thessley-pam-vpn.service           the approval daemon (root): a unix socket for OpenVPN's script + the public QR page
#   /usr/local/lib/thessley-pam/vpn-auth   what OpenVPN's auth-user-pass-verify runs (as OpenVPN's own user, never root)
# The QR page and the device's answers share one HTTPS server on this computer's LAN address, port 47830. Forward that port on
# your router (docs/VPN.md) only when you are ready. Undo: sudo ./uninstall-vpn.sh
set -eu

[ "$(id -u)" = 0 ] || { echo "Run with sudo." >&2; exit 1; }
[ -x /usr/local/sbin/thessley-pam ] || { echo "Run install.sh first." >&2; exit 1; }
command -v qrencode >/dev/null || { echo "Missing qrencode: sudo apt install qrencode" >&2; exit 1; }

install -o root -g root -m 0755 /dev/stdin /usr/local/lib/thessley-pam/vpn-auth <<'WRAP'
#!/bin/sh
# OpenVPN's auth-user-pass-verify (via-env). Runs as OpenVPN's user.
exec /usr/local/sbin/thessley-pam vpn auth
WRAP

unit=/etc/systemd/system/thessley-pam-vpn.service
cat > "$unit" <<'UNIT'
[Unit]
Description=Thessley approval for OpenVPN logins (device approval after the client certificate)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/sbin/thessley-pam vpn serve
Restart=on-failure
RestartSec=5
RuntimeDirectory=thessley-pam
RuntimeDirectoryPreserve=yes
NoNewPrivileges=yes
ProtectHome=yes
PrivateTmp=yes
ProtectSystem=full
ReadWritePaths=/etc/thessley-pam /etc/thessley-pam-enrolled /run/thessley-pam

[Install]
WantedBy=multi-user.target
UNIT
chmod 0644 "$unit"
[ -e /etc/thessley-pam-enrolled ] || install -m 0644 /dev/null /etc/thessley-pam-enrolled
systemctl daemon-reload
echo "Installed $unit (not started)."
echo "Next: sudo thessley-pam vpn public-host NAME ; sudo thessley-pam vpn on   (see docs/VPN.md for OpenVPN itself)"
