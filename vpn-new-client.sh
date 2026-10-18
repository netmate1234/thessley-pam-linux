#!/bin/sh
# Makes a VPN certificate and a ready-to-import profile for one device of one account:
#
#   sudo ./vpn-new-client.sh ACCOUNT DEVICE [OUTPUT.ovpn]         e.g.  sudo ./vpn-new-client.sh ubuntu laptop
#   ./vpn-new-client.sh --dry-run ACCOUNT DEVICE                   only prints what it would do
#
# The certificate is named ACCOUNT@DEVICE. One certificate per device matters: OpenVPN lets one certificate name hold ONE connection,
# so two devices sharing a certificate drop each other's connection ("connection failure" on one when the other connects). The
# server accepts ACCOUNT or ACCOUNT@anything-with-letters-digits-._- for that account (thessley_pam/vpn.py). On the VPN login,
# type ACCOUNT as the user name (any password).
#
# The profile holds the device's PRIVATE KEY: move it to that device over a cable or another trusted channel, then delete the copy.
# It names the public host set with `thessley-pam vpn public-host` (or give HOST=name in the environment).
set -eu
PATH="$PATH:/usr/sbin:/sbin"

DRY=0
[ "${1:-}" = "--dry-run" ] && { DRY=1; shift; }
ACCOUNT="${1:-}"; DEVICE="${2:-}"
[ -n "$ACCOUNT" ] && [ -n "$DEVICE" ] || { echo "usage: sudo $0 ACCOUNT DEVICE [OUTPUT.ovpn]" >&2; exit 2; }
echo "$ACCOUNT" | grep -Eq '^[a-z_][a-z0-9_.-]{0,31}$' || { echo "That is not an account name." >&2; exit 2; }
echo "$DEVICE" | grep -Eq '^[A-Za-z0-9_.-]{1,32}$' || { echo "The device name may have letters, digits and . _ - (up to 32)." >&2; exit 2; }
NAME="$ACCOUNT@$DEVICE"
PKI=/etc/openvpn/easy-rsa-thessley
OUT="${3:-./$ACCOUNT-$DEVICE.ovpn}"

if [ "$DRY" = 1 ]; then
  echo "would make the certificate '$NAME' in $PKI (EC P-256, 825 days) and write the profile $OUT (mode 600)"
  exit 0
fi
[ "$(id -u)" = 0 ] || { echo "Run with sudo." >&2; exit 1; }
[ -d "$PKI/pki" ] || { echo "No VPN certificate authority at $PKI: set the VPN up first (docs/VPN.md)." >&2; exit 1; }
getent passwd "$ACCOUNT" >/dev/null || { echo "No such account on this computer: $ACCOUNT" >&2; exit 1; }
HOST="${HOST:-$(/usr/local/sbin/thessley-pam vpn status | sed -n 's/.*link host \([^ ]*\).*/\1/p' | head -1)}"
[ -n "$HOST" ] || { echo "Set the public host first: sudo thessley-pam vpn public-host NAME" >&2; exit 1; }

cd "$PKI"
export EASYRSA_BATCH=1 EASYRSA_ALGO=ec EASYRSA_CURVE=prime256v1
if [ ! -f "pki/issued/$NAME.crt" ]; then
  EASYRSA_CERT_EXPIRE=825 ./easyrsa build-client-full "$NAME" nopass >/dev/null 2>&1
fi
umask 077
cat > "$OUT" <<PROFILE
client
dev tun
proto udp
remote $HOST 1194
remote-cert-tls server
auth-user-pass
auth-nocache
data-ciphers AES-256-GCM:CHACHA20-POLY1305
<ca>
$(cat pki/ca.crt)
</ca>
<cert>
$(openssl x509 -in "pki/issued/$NAME.crt")
</cert>
<key>
$(cat "pki/private/$NAME.key")
</key>
<tls-crypt>
$(cat pki/ta.key)
</tls-crypt>
PROFILE
if [ -n "${SUDO_USER:-}" ]; then chown "$SUDO_USER" "$OUT" 2>/dev/null || true; fi
echo "Made the certificate $NAME and the profile $OUT. User name to type on connect: $ACCOUNT (any password)."
echo "The profile holds the private key: move it to the device by a trusted channel, then delete this copy."
