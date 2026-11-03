#!/usr/bin/env bash
# Guided Ubuntu 24.04/26.04 and Debian 13 OpenVPN setup with Thessley phone approval.
# Run as root from a terminal. This creates a separate OpenVPN instance named
# thessley; it refuses to overwrite an existing Thessley OpenVPN config/PKI.
set -Eeuo pipefail
umask 077

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die 'Run with sudo: sudo bash install-openvpn-server.sh'
[[ -x /usr/local/sbin/thessley-pam ]] || die 'Install the Thessley Linux package first (Linux installation guide).'
src=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
[[ -r /etc/os-release ]] || die 'Cannot identify this Linux distribution.'
. /etc/os-release
case "${ID:-}:${VERSION_ID:-}" in
  ubuntu:24.04|ubuntu:26.04|debian:13) ;;
  *) die 'This guided setup supports Ubuntu 24.04/26.04 LTS and Debian 13 (including Armbian based on Debian 13).' ;;
esac

CONF=/etc/openvpn/server/thessley.conf
PKI=/etc/openvpn/easy-rsa-thessley
VPN_UNIT=/etc/systemd/system/thessley-pam-vpn.service
[[ ! -e $CONF ]] || die "Refusing to overwrite existing VPN config ($CONF). Follow docs/VPN.md to adapt an existing server."
[[ ! -e $VPN_UNIT ]] || die "The Thessley VPN approval service already exists. Use the manual upgrade/adaptation steps rather than replacing it."
PKI_RESUME=no
if [[ -e $PKI ]]; then
  [[ -d $PKI && -f $PKI/pki/ca.crt && -f $PKI/pki/private/ca.key && -x $PKI/easyrsa ]] \
    || die "An incomplete Easy-RSA directory exists at $PKI but has no usable CA. Preserve it and resolve it manually; the installer will not replace it."
  PKI_RESUME=yes
  printf 'Found an existing Thessley CA at %s; it will be preserved and reused.\n' "$PKI"
fi


read -r -p 'Public DNS name or IP address reachable by your phone: ' HOST
[[ -n $HOST ]] || die 'A real public DNS name or IP address is required; do not use an example value.'
[[ $HOST =~ ^[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]$|^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || die 'Enter a DNS hostname or IPv4 address (no scheme or port).'
read -r -p "Linux account that will approve logins [${SUDO_USER:-ubuntu}]: " ACCOUNT
ACCOUNT=${ACCOUNT:-${SUDO_USER:-ubuntu}}
getent passwd "$ACCOUNT" >/dev/null || die "No such local account: $ACCOUNT"
[[ $ACCOUNT =~ ^[a-z_][a-z0-9_.-]{0,31}$ ]] || die 'Use a Linux account name with lowercase letters, digits, dot, underscore or hyphen.'
ACCOUNT_HOME=$(getent passwd "$ACCOUNT" | cut -d: -f6)
[[ -n $ACCOUNT_HOME && -d $ACCOUNT_HOME ]] || die "The account home directory is missing: $ACCOUNT_HOME"
LAN_DEFAULT=none
if command -v ip >/dev/null 2>&1; then
  DEFAULT_IF=$(ip -4 route show default | awk 'NR == 1 { for (i=1; i<NF; i++) if ($i == "dev") { print $(i+1); exit } }')
  if [[ -n $DEFAULT_IF ]]; then
    LAN_CANDIDATE=$(ip -4 route show dev "$DEFAULT_IF" proto kernel | awk '$1 ~ /^[0-9.]+\/[0-9]+$/ { print $1; exit }')
    if [[ -n $LAN_CANDIDATE ]] && python3 -c 'import ipaddress,sys; n=ipaddress.ip_network(sys.argv[1], strict=True); rfc1918=any(n.subnet_of(ipaddress.ip_network(c)) for c in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")); sys.exit(0 if n.version == 4 and rfc1918 else 1)' "$LAN_CANDIDATE" 2>/dev/null; then
      LAN_DEFAULT=$LAN_CANDIDATE
    fi
  fi
fi
SUBNET_DEFAULT=10.8.0.0/24
for candidate in 10.8.0.0/24 10.9.0.0/24 10.10.0.0/24 10.11.0.0/24 172.31.250.0/24 192.168.250.0/24; do
  if [[ $LAN_DEFAULT == none ]] || python3 -c 'import ipaddress,sys; a=ipaddress.ip_network(sys.argv[1]); b=ipaddress.ip_network(sys.argv[2]); sys.exit(0 if not a.overlaps(b) else 1)' "$candidate" "$LAN_DEFAULT" 2>/dev/null; then
    SUBNET_DEFAULT=$candidate
    break
  fi
done
read -r -p "VPN tunnel subnet [$SUBNET_DEFAULT] (avoid any other networks used by clients): " SUBNET
SUBNET=${SUBNET:-$SUBNET_DEFAULT}
python3 -c 'import ipaddress,sys; n=ipaddress.ip_network(sys.argv[1], strict=True); ok=n.version == 4 and n.prefixlen == 24; sys.exit(0 if ok else 1)' "$SUBNET" 2>/dev/null \
  || die 'Enter a valid IPv4 /24 network, for example 10.8.0.0/24.'
read -r -p "LAN subnet VPN clients should reach [$LAN_DEFAULT; type none to skip]: " LAN_ROUTE
LAN_ROUTE=${LAN_ROUTE:-$LAN_DEFAULT}
if [[ $LAN_ROUTE != none ]]; then
  LAN_ROUTE_DETAILS=$(python3 -c 'import ipaddress,sys; lan=ipaddress.ip_network(sys.argv[1], strict=True); vpn=ipaddress.ip_network(sys.argv[2], strict=True); sys.exit(2) if lan.version != 4 or lan.overlaps(vpn) else print(lan.network_address, lan.netmask)' "$LAN_ROUTE" "$SUBNET" 2>/dev/null) \
    || die 'Enter a valid IPv4 network that does not overlap the VPN tunnel, or type none.'
  LAN_NETWORK=${LAN_ROUTE_DETAILS% *}
  LAN_NETMASK=${LAN_ROUTE_DETAILS#* }
fi
read -r -p 'OpenVPN UDP port [1194]: ' PORT
PORT=${PORT:-1194}
[[ $PORT =~ ^[0-9]{1,5}$ ]] && (( PORT >= 1 && PORT <= 65535 )) || die 'Enter a UDP port from 1 to 65535.'
read -r -p 'Device label for the first client profile [phone]: ' DEVICE
DEVICE=${DEVICE:-phone}
[[ $DEVICE =~ ^[A-Za-z0-9_.-]{1,32}$ ]] || die 'Device label may contain letters, numbers, dot, underscore and hyphen (up to 32).'

printf '\nThis will install OpenVPN/Easy-RSA and create a new isolated server instance on Ubuntu 24.04/26.04 LTS or Debian 13.\n'
printf 'It will not change SSH/PAM, router settings, or an existing OpenVPN configuration.\n'
printf 'Phone approval page: TCP 47830. VPN transport: UDP %s.\n' "$PORT"
if [[ ${THESSLEY_GUIDED_VPN_APPROVED:-0} != 1 ]]; then
  read -r -p 'Continue with this VPN setup and the listed firewall changes? [y/N] ' CONFIRM
  [[ $CONFIRM == y || $CONFIRM == Y ]] || exit 0
fi
UFW_ALLOW=no
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
  printf '\nUFW is active. Continuing adds only inbound UDP %s and TCP 47830 (phone approvals).\n' "$PORT"
  UFW_ALLOW=yes
else
  printf '\nUFW is not active; no host firewall was changed. Ensure another firewall allows UDP %s and TCP 47830.\n' "$PORT"
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y openvpn easy-rsa qrencode
unset EASYRSA_BATCH EASYRSA_PASSIN EASYRSA_PASSOUT
if [[ $PKI_RESUME == yes ]]; then
  MIGRATE_CA=/opt/thessley-pam-linux/migrate-vpn-ca-unencrypted.sh
  [[ -f $MIGRATE_CA ]] || die "This encrypted CA must be migrated once. Run: sudo bash /opt/thessley-pam-linux/migrate-vpn-ca-unencrypted.sh"
  bash "$MIGRATE_CA"
fi

"$src/prepare-enrolled-list.sh"

install -d -o root -g root -m 0755 /etc/openvpn/server
if [[ $PKI_RESUME == no ]]; then
  install -d -o root -g root -m 0755 "$PKI"
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
  EASYRSA_BATCH=1 EASYRSA_REQ_CN='Thessley OpenVPN CA' ./easyrsa build-ca nopass
else
  chown -R root:root "$PKI"
  chmod 700 "$PKI"
fi
cd "$PKI"
export EASYRSA_ALGO=ec EASYRSA_CURVE=prime256v1
if [[ ! -f pki/issued/server.crt ]]; then
  if [[ -f pki/reqs/server.req && -f pki/private/server.key ]]; then
    ./easyrsa sign-req server server
  else
    ./easyrsa build-server-full server nopass
  fi
fi
if [[ ! -f pki/crl.pem ]]; then
  EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
fi
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
if [[ $LAN_ROUTE != none ]]; then
  printf 'push "route %s %s"\n' "$LAN_NETWORK" "$LAN_NETMASK" >> "$CONF"
fi
chmod 0644 "$CONF"

# Keep the CA and its PKI writable by root for future Easy-RSA operations, and
# inaccessible to the dropped-privilege OpenVPN process. OpenVPN reads its
# public CA/CRL and server key material from /etc/openvpn/server, not this tree.
chmod 0700 "$PKI" "$PKI/pki"
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
ReadWritePaths=/etc/thessley-pam /var/lib/thessley-pam /run/thessley-pam-vpn

[Install]
WantedBy=multi-user.target
UNIT
chmod 0644 "$VPN_UNIT"
systemctl daemon-reload
/usr/local/sbin/thessley-pam vpn public-host "$HOST"
/usr/local/sbin/thessley-pam vpn server-port "$PORT"
/usr/local/sbin/thessley-pam vpn page-port 47830

# Enable the approval endpoint before the interactive phone enrollment. If
# enrollment is delayed or interrupted, Admin still shows the installed VPN
# and can issue a client key; logins remain refused until an approving phone
# is associated with the VPN host.
/usr/local/sbin/thessley-pam vpn on
install -d -o root -g root -m 0700 "$PKI" "$PKI/pki"
install -o root -g root -m 0644 "$PKI/pki/crl.pem" /etc/openvpn/server/crl.pem

# systemd applies ReadWritePaths when it creates the web service mount
# namespace. The web service may have started before this PKI existed, so
# refresh it now to enable future VPN client certificate issuance.
if systemctl is-active --quiet thessley-pam-web.service; then
  echo 'Refreshing the Thessley web service sandbox for the new VPN PKI...'
  systemctl restart thessley-pam-web.service
fi

systemctl enable --now openvpn-server@thessley
if [[ $UFW_ALLOW == yes ]]; then
  ufw allow "$PORT/udp" comment 'Thessley OpenVPN transport'
  ufw allow 47830/tcp comment 'Thessley VPN phone approvals'
fi

printf '\nEnroll the approving phone for %s. Scan its QR code and confirm the matching codes.\n' "$HOST"
/usr/local/sbin/thessley-pam vpn enroll "$ACCOUNT"

PROFILE="${ACCOUNT_HOME%/}/$ACCOUNT-$DEVICE.ovpn"
cd "$PKI"
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
<auth-user-pass>
$ACCOUNT
thessley-qr-login
</auth-user-pass>
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
printf 'Forward UDP %s and TCP 47830 on the router to this server for remote VPN login and phone approval.\n' "$PORT"
if [[ $LAN_ROUTE != none ]]; then
  printf 'The server pushes route %s to VPN clients. The guided installer enables VPN-to-LAN forwarding/NAT by default; answer n to skip it.\n' "$LAN_ROUTE"
fi
printf 'The first approved login creates an OpenVPN reconnect token: renewed hourly, maximum 8 hours.\n'
