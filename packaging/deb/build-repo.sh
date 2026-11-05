#!/bin/sh
# Build the source-staging .deb and a signed apt repository for Ubuntu LTS systems.
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
version=${1:-}
out=${2:-}
key=${3:-${THESSLEY_APT_SIGNING_KEY:-}}

if [ -z "$version" ] || [ -z "$out" ] || [ -z "$key" ]; then
    echo "Usage: $0 VERSION OUTPUT_DIR SIGNING_KEY_ID" >&2
    exit 2
fi
case "$version" in *[!0-9A-Za-z.+:~_-]*|'') echo "Invalid Debian version: $version" >&2; exit 2;; esac
command -v dpkg-deb >/dev/null || { echo "Install dpkg-deb." >&2; exit 1; }
command -v dpkg-scanpackages >/dev/null || { echo "Install dpkg-dev." >&2; exit 1; }
command -v apt-ftparchive >/dev/null || { echo "Install apt-utils." >&2; exit 1; }
command -v gpg >/dev/null || { echo "Install gnupg." >&2; exit 1; }
gpg --list-secret-keys "$key" >/dev/null 2>&1 || { echo "Signing key not found: $key" >&2; exit 1; }

out=$(mkdir -p "$out" && CDPATH= cd -- "$out" && pwd)
work=$(mktemp -d)
pkg="$work/pkg"
repo="$work/repo"
name=thessley-pam-linux-installer
deb="$name"_"$version"_all.deb
mkdir -p "$pkg/DEBIAN" "$pkg/opt/thessley-pam-linux" "$pkg/usr/share/doc/$name" \
    "$pkg/usr/local/sbin" \
    "$repo/pool/main/t/$name" "$repo/dists/stable/main/binary-amd64" "$repo/dists/stable/main/binary-arm64"

cat > "$pkg/DEBIAN/control" <<CONTROL
Package: $name
Version: $version
Section: admin
Priority: optional
Architecture: all
Maintainer: Thessley Security Projects
Homepage: https://wp-opsec.eagleeye-intelligence.com/
Depends: python3 (>= 3.10), qrencode, python3-cryptography, python3-asn1crypto, systemd
Description: Thessley phone-approved Linux sign-in source and installer
 Installs the source and installation scripts under /opt/thessley-pam-linux.
 It does not enable services or change SSH, PAM, VPN, or firewall policy.
CONTROL

cat > "$pkg/usr/share/doc/$name/README.Debian" <<'DOC'
Thessley Linux source installer package

The package stages source under /opt/thessley-pam-linux and installs runtime
dependencies. It makes no service, firewall, SSH, PAM, or VPN configuration
changes. Run the guided installer to install the shared approval service and
choose optional integrations:

  sudo thessley-pam-install

The HTTPS web admin page is enabled by default (answer n to skip); other
optional choices default to No. The guided installer does not edit SSH login
policy or overwrite existing OpenVPN configuration. It supports Ubuntu 24.04,
Ubuntu 26.04, and Debian 13. It can optionally create a new isolated OpenVPN
server with Thessley QR approval. VPN-to-LAN forwarding/NAT is enabled
automatically when a LAN route is selected; enter none to skip LAN access. To run it from the
source directory:

  sudo ./guided-install.sh

GNOME login QR approval leaves GDM password fallback enabled by default. If
the Thessley Login admin app is installed, first test QR login with fallback
still on, then use its QR-only GNOME login switch to block password login.
Only accounts with an enrolled, working phone can use QR-only mode; keep
console or another administrator access available. `sudo ./uninstall-login.sh`
restores password fallback before removing the QR service.

The shared service starts a 60-minute installation-approval timer after its
health check. Verify the phone approval and web page, then approve in Admin or
run `sudo thessley-install-rollback approve`; otherwise previous core app files
and service state are restored. For SSH/PAM policy changes, see docs/SSH.md.

Removing this package removes the staged source and documentation only. If
install.sh or an optional component installer was run, use its documented
uninstall procedure before removing the source package.
DOC

tar -C "$root" --exclude=.git --exclude=.codegraph --exclude=tests --exclude='*/__pycache__' --exclude=.pytest_cache \
    -cf - . | tar -C "$pkg/opt/thessley-pam-linux" -xf -
cat > "$pkg/usr/local/sbin/thessley-pam-install" <<'WRAPPER'
#!/bin/sh
exec /opt/thessley-pam-linux/guided-install.sh "$@"
WRAPPER
chmod 0644 "$pkg/DEBIAN/control" "$pkg/usr/share/doc/$name/README.Debian"
chmod 0755 "$pkg/usr/local/sbin/thessley-pam-install"
dpkg-deb --build --root-owner-group "$pkg" "$repo/pool/main/t/$name/$deb" >/dev/null

for arch in amd64 arm64; do
    (cd "$repo" && dpkg-scanpackages --arch all pool /dev/null) > "$repo/dists/stable/main/binary-$arch/Packages"
    gzip -n -9 -c "$repo/dists/stable/main/binary-$arch/Packages" > "$repo/dists/stable/main/binary-$arch/Packages.gz"
done

(
    cd "$repo"
    apt-ftparchive \
        -o APT::FTPArchive::Release::Origin="Thessley Security Projects" \
        -o APT::FTPArchive::Release::Label="Thessley Linux" \
        -o APT::FTPArchive::Release::Suite=stable \
        -o APT::FTPArchive::Release::Codename=stable \
        -o APT::FTPArchive::Release::Architectures="amd64 arm64" \
        -o APT::FTPArchive::Release::Components=main \
        release dists/stable > dists/stable/Release
    gpg --batch --yes --local-user "$key" --clearsign --output dists/stable/InRelease dists/stable/Release
    gpg --batch --yes --local-user "$key" --armor --detach-sign --output dists/stable/Release.gpg dists/stable/Release
    gpg --batch --export "$key" > thessley-archive-keyring.gpg
)

mkdir -p "$out"
cp -a "$repo/." "$out/"
printf '%s\n' "$version" > "$out/THESSLEY_VERSION"
echo "Built $out/pool/main/t/$name/$deb"
echo "Signed apt repository is in $out"
