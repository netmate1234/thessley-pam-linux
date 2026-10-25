#!/usr/bin/env bash
# One-time conversion for an existing encrypted Thessley CA key. The same CA
# key and certificate are retained; only the at-rest encryption is removed.
set -Eeuo pipefail
umask 077

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die 'Run with sudo: sudo bash migrate-vpn-ca-unencrypted.sh'

PKI=/etc/openvpn/easy-rsa-thessley/pki
KEY="$PKI/private/ca.key"
CERT="$PKI/ca.crt"
[[ -s $KEY && -s $CERT ]] || die "Thessley CA key or certificate is missing under $PKI."

if openssl pkey -in "$KEY" -passin pass: -noout >/dev/null 2>&1; then
  owner=$(stat -c '%u:%g:%a' "$KEY")
  [[ $owner == 0:0:600 ]] || { chown root:root "$KEY"; chmod 0600 "$KEY"; }
  echo 'The CA key is already unencrypted and root-only; no change was needed.'
  exit 0
fi

PASS_FILE=$(mktemp /run/thessley-ca-passphrase.XXXXXX)
PLAIN_TMP=$(mktemp "$PKI/private/.ca-key-unencrypted.XXXXXX")
cleanup() {
  [[ ! -e ${PASS_FILE:-} ]] || shred -u "$PASS_FILE" 2>/dev/null || rm -f "$PASS_FILE"
  [[ ! -e ${PLAIN_TMP:-} ]] || shred -u "$PLAIN_TMP" 2>/dev/null || rm -f "$PLAIN_TMP"
  unset CA_PASSPHRASE
}
trap cleanup EXIT
chmod 0600 "$PASS_FILE" "$PLAIN_TMP"

read -r -s -p 'Current Thessley CA passphrase (used once for this conversion): ' CA_PASSPHRASE </dev/tty
printf '\n' >/dev/tty
[[ -n $CA_PASSPHRASE ]] || die 'The CA passphrase cannot be empty.'
printf '%s' "$CA_PASSPHRASE" > "$PASS_FILE"
unset CA_PASSPHRASE

if ! openssl pkey -in "$KEY" -passin "file:$PASS_FILE" -out "$PLAIN_TMP" 2>/dev/null; then
  die 'The passphrase was not accepted; the existing CA key was not changed.'
fi
if ! openssl pkey -in "$PLAIN_TMP" -passin pass: -noout >/dev/null 2>&1; then
  die 'The converted key did not validate; the existing CA key was not changed.'
fi

key_fingerprint=$(openssl pkey -in "$PLAIN_TMP" -pubout -outform DER | sha256sum | awk '{print $1}')
cert_fingerprint=$(openssl x509 -in "$CERT" -noout -pubkey | openssl pkey -pubin -outform DER | sha256sum | awk '{print $1}')
[[ -n $key_fingerprint && $key_fingerprint == "$cert_fingerprint" ]] \
  || die 'The CA private key does not match its certificate; the existing key was not changed.'

backup_dir=/var/backups/thessley-encrypted-ca
install -d -o root -g root -m 0700 "$backup_dir"
backup="$backup_dir/ca.key.$(date +%Y%m%d-%H%M%S).encrypted"
[[ ! -e $backup ]] || die "Encrypted backup already exists: $backup"
install -o root -g root -m 0600 "$KEY" "$backup"
chown root:root "$PLAIN_TMP"
chmod 0600 "$PLAIN_TMP"
mv -f "$PLAIN_TMP" "$KEY"
PLAIN_TMP=

echo 'CA key converted. The CA certificate and existing server/client certificates are unchanged.'
echo "Encrypted original retained at $backup (root-only)."
echo 'Web VPN key creation and revocation can now sign without asking for a passphrase.'
