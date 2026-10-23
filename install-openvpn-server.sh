#!/usr/bin/env bash
# Guided Ubuntu 24.04 OpenVPN server setup with Thessley phone approval.
# Run as root from a terminal. This creates a separate OpenVPN instance named
# thessley; it refuses to overwrite an existing Thessley OpenVPN config/PKI.
set -Eeuo pipefail
umask 077

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die 'Run with sudo: sudo bash install-openvpn-server.sh'
[[ -x /usr/local/sbin/thessley-pam ]] || die 'Install the Thessley Linux package first (Linux installation guide).'
[[ -r /etc/os-release ]] || die 'Cannot identify this Linux distribution.'
. /etc/os-release
[[ ${ID:-} == ubuntu && ${VERSION_ID:-} == 24.04 ]] || die 'This guided setup currently supports Ubuntu 24.04 LTS only.'

CONF=/etc/openvpn/server/thessley.conf
PKI=/etc/openvpn/easy-rsa-thessley
[[ ! -e $CONF && ! -e $PKI ]] || die "Refusing to overwrite existing VPN files ($CONF or $PKI). Back them up and follow docs/VPN.md to adapt an existing server."
VPN_UNIT=/etc/systemd/system/thessley-pam-vpn.service
[[ ! -e $VPN_UNIT ]] || die "The Thessley VPN approval service already exists. Use the manual upgrade/adaptation steps rather than replacing it."

read -r -p 'Public DNS name or IP address reachable by your phone: ' HOST
[[ -n $HOST ]] || die 'A real public DNS name or IP address is required; do not use an example value.'
[[ $HOST =~ ^[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]$|^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || die 'Enter a DNS hostname or IPv4 address (no scheme or port).'
read -r -p "Linux account that will approve logins [${SUDO_USER:-ubuntu}]: " ACCOUNT
ACCOUNT=${ACCOUNT:-${SUDO_USER:-ubuntu}}
getent passwd "$ACCOUNT" >/dev/null || die "No such local account: $ACCOUNT"
[[ $ACCOUNT =~ ^[a-z_][a-z0-9_.-]{0,31}$ ]] || die 'Use a Linux account name with lowercase letters, digits, dot, underscore or hyphen.'
ACCOUNT_HOME=$(getent passwd "$ACCOUNT" | cut -d: -f6)
[[ -n $ACCOUNT_HOME && -d $ACCOUNT_HOME ]] || die "The account home directory is missing: $ACCOUNT_HOME"
read -r -p 'VPN tunnel subnet [10.8.0.0/24] (check it does not overlap your LAN/other VPN): ' SUBNET
SUBNET=${SUBNET:-10.8.0.0/24}
[[ $SUBNET =~ ^([0-9]{1,3}\.){3}0/24$ ]] || die 'Enter an IPv4 /24 network, for example 10.8.0.0/24.'
read -r -p 'OpenVPN UDP port [1194]: ' PORT
PORT=${PORT:-1194}
[[ $PORT =~ ^[0-9]{1,5}$ ]] && (( PORT >= 1 && PORT <= 65535 )) || die 'Enter a UDP port from 1 to 65535.'
read -r -p 'Device label for the first client profile [phone]: ' DEVICE
DEVICE=${DEVICE:-phone}
[[ $DEVICE =~ ^[A-Za-z0-9_.-]{1,32}$ ]] || die 'Device label may contain letters, numbers, dot, underscore and hyphen (up to 32).'

printf '\nThis will install OpenVPN/Easy-RSA and create a new isolated server instance.\n'
printf 'It will not change SSH/PAM, router settings, or an existing OpenVPN configuration.\n'
printf 'Phone approval page: TCP 47830. VPN transport: UDP %s.\n' "$PORT"
read -r -p 'Continue? [y/N] ' CONFIRM
[[ $CONFIRM == y || $CONFIRM == Y ]] || exit 0

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y openvpn easy-rsa qrencode

install -d -o root -g root -m 0755 /etc/openvpn/server "$PKI"
if [[ -d /usr/share/easy-rsa ]]; then
  cp -a /usr/share/easy-rsa/. "$PKI/"
elif command -v make-cadir >/dev/null 2>&1; then
  rmdir "$PKI"
  make-cadir "$PKI"
else
  die 'Easy-RSA was installed but its files were not found.'
fi
chown -R root:root "$PKI"
chmod 700 "$PKI"
cd "$PKI"
export EASYRSA_ALGO=ec EASYRSA_CURVE=prime256v1
./easyrsa init-pki
printf '\nCreate a strong passphrase for the offline certificate authority when prompted.\n'
./easyrsa build-ca
EASYRSA_BATCH=1 ./easyrsa build-server-full server nopass
EASYRSA_BATCH=1 EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
openvpn --genkey secret pki/ta.key

install -d -o root -g root -m 0755 /etc/openvpn/server
install -o root -g root -m 0644 pki/ca.crt /etc/openvpn/server/ca.crt
install -o root -g root -m 0644 pki/issued/server.crt /etc/openvpn/server/server.crt
install -o root -g root -m 0600 pki/private/server.key /etc/openvpn/server/server.key
install -o root -g root -m 0600 pki/ta.key /etc/openvpn/server/ta.key
install -o root -g root -m 0600 pki/crl.pem /etc/openvpn/server/crl.pem
/usr/sbin/openvpn --genkey auth-token /etc/openvpn/server/thessley-auth-token.key
chown root:root /etc/openvpn/server/thessley-auth-token.key
chmod 0600 /etc/openvpn/server/thessley-auth-token.key

IFS=. read -r a b c d <<< "${SUBNET%/*}"
for octet in "$a" "$b" "$c" "$d"; do (( 10#$octet <= 255 )) || die 'Invalid IPv4 address in tunnel subnet.'; done
cat > "$CONF" <<EOF
port $PORT
proto udp
dev tun
topology subnet
server ${SUBNET%/*} 255.255.255.0
ca ca.crt
cert server.crt
key server.key
dh none
tls-crypt ta.key
tls-version-min 1.2
remote-cert-tls client
verify-client-cert require
crl-verify /etc/openvpn/server/crl.pem
management /run/openvpn-server/thessley.mgmt unix
management-client-user root
script-security 2
auth-user-pass-verify /usr/local/lib/thessley-pam/vpn-auth via-env
auth-gen-token 28800 3600
auth-gen-token-secret /etc/openvpn/server/thessley-auth-token.key
reneg-sec 3600
push "reneg-sec 3600"
user nobody
group nogroup
keepalive 10 300
persist-key
persist-tun
verb 3
EOF
chmod 0644 "$CONF"

# Ensure the CA tree is traversable by the dropped-privilege OpenVPN process,
# without making any private key readable to it.
chmod 0711 "$PKI" "$PKI/pki"
chmod 0644 "$PKI/pki/crl.pem"

# Install the Thessley OpenVPN approval helper and its dedicated daemon.
install -d -o root -g root -m 0755 /usr/local/lib/thessley-pam
cat > /usr/local/lib/thessley-pam/vpn-auth <<'WRAP'
#!/bin/sh
exec /usr/local/sbin/thessley-pam vpn auth
WRAP
chown root:root /usr/local/lib/thessley-pam/vpn-auth
chmod 0755 /usr/local/lib/thessley-pam/vpn-auth
cat > "$VPN_UNIT" <<'UNIT'
[Unit]
Description=Thessley approval for OpenVPN logins
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/sbin/thessley-pam vpn serve
Restart=on-failure
RestartSec=5
RuntimeDirectory=thessley-pam-vpn
RuntimeDirectoryMode=0750
RuntimeDirectoryPreserve=yes
Group=nogroup
ExecStartPre=/usr/bin/chown root:nogroup /run/thessley-pam-vpn
ExecStartPre=/usr/bin/chmod 0750 /run/thessley-pam-vpn
NoNewPrivileges=yes
ProtectHome=yes
PrivateTmp=yes
ProtectSystem=full
ReadWritePaths=/etc/thessley-pam /etc/thessley-pam-enrolled /run/thessley-pam-vpn

[Install]
WantedBy=multi-user.target
UNIT
chmod 0644 "$VPN_UNIT"
[[ -e /etc/thessley-pam-enrolled ]] || install -o root -g root -m 0644 /dev/null /etc/thessley-pam-enrolled
systemctl daemon-reload
systemctl enable --now thessley-pam-vpn.service
/usr/local/sbin/thessley-pam vpn public-host "$HOST"
/usr/local/sbin/thessley-pam vpn page-port 47830

printf '\nEnroll the approving phone for %s. Scan its QR code and confirm the matching codes.\n' "$HOST"
/usr/local/sbin/thessley-pam vpn enroll "$ACCOUNT"
/usr/local/sbin/thessley-pam vpn on

install -d -o root -g root -m 0711 "$PKI" "$PKI/pki"
install -o root -g root -m 0644 "$PKI/pki/crl.pem" /etc/openvpn/server/crl.pem
systemctl enable --now openvpn-server@thessley

PROFILE="${ACCOUNT_HOME%/}/$ACCOUNT-$DEVICE.ovpn"
cd "$PKI"
export EASYRSA_BATCH=1
./easyrsa build-client-full "$ACCOUNT@$DEVICE" nopass
CA=$(cat pki/ca.crt)
CERT=$(openssl x509 -in "pki/issued/$ACCOUNT@$DEVICE.crt")
KEY=$(cat "pki/private/$ACCOUNT@$DEVICE.key")
TA=$(cat pki/ta.key)
install -o "$ACCOUNT" -g "$(id -gn "$ACCOUNT")" -m 0600 /dev/null "$PROFILE"
cat > "$PROFILE" <<EOF
client
dev tun
proto udp
remote $HOST $PORT
remote-cert-tls server
auth-user-pass
auth-nocache
data-ciphers AES-256-GCM:CHACHA20-POLY1305
<ca>
$CA
</ca>
<cert>
$CERT
</cert>
<key>
$KEY
</key>
<tls-crypt>
$TA
</tls-crypt>
EOF
chown "$ACCOUNT:$(id -gn "$ACCOUNT")" "$PROFILE"
chmod 0600 "$PROFILE"

printf '\nOpenVPN service: '
systemctl --no-pager --full status openvpn-server@thessley | sed -n '1,3p'
printf '\nSetup complete.\nProfile: %s (contains a private key; transfer securely, then delete it here).\n' "$PROFILE"
printf 'Configure the router to forward UDP %s and TCP 47830 to this server.\n' "$PORT"
printf 'If UFW is active, allow only these ports: sudo ufw allow %s/udp && sudo ufw allow 47830/tcp\n' "$PORT"
printf 'The first approved login creates an OpenVPN reconnect token: renewed hourly, maximum 8 hours.\n'
