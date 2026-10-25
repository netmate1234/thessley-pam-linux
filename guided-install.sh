#!/bin/sh
# Interactive Ubuntu/Debian installer. Installs the required shared service and
# offers optional integrations one by one. It never edits sshd_config or PAM
# login policy (the GNOME option creates its separate password-preserving PAM
# service through install-login.sh).
set -eu

[ "$(id -u)" = 0 ] || { echo "Run with sudo: sudo thessley-pam-install" >&2; exit 1; }
[ -r /dev/tty ] || { echo "Run this installer from an interactive terminal." >&2; exit 1; }

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -x "$script_dir/install.sh" ]; then
    src=$script_dir
elif [ -x /opt/thessley-pam-linux/install.sh ]; then
    src=/opt/thessley-pam-linux
else
    echo "Cannot find the Thessley source files." >&2
    exit 1
fi

ask() {
    while :; do
        printf '%s [y/N] ' "$1" > /dev/tty
        IFS= read -r answer < /dev/tty || return 1
        case "$answer" in
            y|Y|yes|YES|Yes) return 0 ;;
            ''|n|N|no|NO|No) return 1 ;;
            *) echo "Please answer y or n." > /dev/tty ;;
        esac
    done
}

install_packages() {
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@"
}

cat <<'INTRO'
Thessley guided setup

The shared phone-approval service is required. Optional features are asked
below and default to No. This installer does not modify existing sshd_config
or PAM login stacks, or OpenVPN server configuration. It only adds firewall
rules if you explicitly choose the VPN-to-LAN forwarding option. The GNOME
option creates its own password-preserving PAM service and does not replace
the normal password login.
INTRO

echo "Clock diagnostic (informational only; it never blocks setup)..."
python3 - <<'PY'
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.request import Request, urlopen

try:
    request = Request(
        "https://wp-opsec.eagleeye-intelligence.com/",
        method="HEAD",
        headers={"Cache-Control": "no-cache"},
    )
    with urlopen(request, timeout=8) as response:
        header = response.headers.get("Date")
    if not header:
        raise RuntimeError("the HTTPS server returned no Date header")
    reference = parsedate_to_datetime(header).astimezone(timezone.utc)
    local = datetime.now(timezone.utc)
    delta = round((local - reference).total_seconds())
    print(
        "System UTC "
        f"{local:%Y-%m-%d %H:%M:%S}; reference HTTP Date UTC "
        f"{reference:%Y-%m-%d %H:%M:%S}; difference {delta}s."
    )
    if abs(delta) > 60:
        print(
            "WARNING: continuing. This comparison cannot tell which clock is inaccurate; "
            "time-zone settings are not part of it."
        )
except Exception as exc:
    print(f"WARNING: clock comparison unavailable ({exc}); continuing.")
PY
export THESSLEY_CLOCK_DIAGNOSTIC_DONE=1

echo "Updating package lists and installing required runtime dependencies..."
apt-get update
install_packages qrencode python3-cryptography python3-asn1crypto

echo "Installing the shared approval service..."
"$src/install.sh"

target_user=${SUDO_USER:-}
if [ -n "$target_user" ] && getent passwd "$target_user" >/dev/null 2>&1; then
    if ask "Enroll a phone for account $target_user now?"; then
        if ! /usr/local/sbin/thessley-pam enroll --user "$target_user"; then
            echo "Enrollment did not finish. You can retry with: sudo thessley-pam enroll --user $target_user"
        fi
    fi
else
    echo "To enroll a phone later, run: sudo thessley-pam enroll --user ACCOUNT"
fi

if ask "Install the HTTPS web admin page? It stays off until separately enabled."; then
    "$src/install-web.sh"
    if ask "Start and enable the web admin page now on its configured address and TCP port 47820?"; then
        /usr/local/sbin/thessley-pam web on
        /usr/local/sbin/thessley-pam web status
        echo "Restrict TCP port 47820 to trusted networks in your firewall."
    fi
fi

admin_installed=no
if ask "Install the Thessley Login desktop admin app (GTK/libadwaita required)?"; then
    install_packages python3-gi gir1.2-adw-1 policykit-1
    "$src/install-admin.sh"
    admin_installed=yes
fi

ssh_installed=no
if ask "Install the SSH phone-authentication module? This does not change SSH or PAM login policy."; then
    install_packages build-essential libpam0g-dev
    "$src/install-ssh.sh"
    ssh_installed=yes
fi

login_installed=no
if ask "Install QR approval on the GNOME login screen? The normal password remains available."; then
    if [ ! -x /usr/share/gdm/generate-config ] || [ ! -f /etc/gdm3/greeter.dconf-defaults ]; then
        echo "GDM configuration is not present; skipping GNOME login integration."
    else
        "$src/install-login.sh"
        login_installed=yes
    fi
fi

if [ "$login_installed" = yes ] && ask "Install optional TPM-backed GNOME keyring unlock support? It will not seal a password or edit PAM login rules yet."; then
    install_packages build-essential libpam0g-dev tpm2-tools
    "$src/install-keyring.sh"
    echo "After enrolling a phone, link the login password explicitly with: sudo thessley-pam keyring-link"
fi

if ask "Allow users to enroll their own first phone without sudo password? This adds a narrow NOPASSWD sudoers rule."; then
    "$src/install-selfenroll.sh"
fi

vpn_installed=no
if ask "Install the OpenVPN QR-approval service hook? This does not configure or start an OpenVPN server."; then
    install_packages openvpn easy-rsa
    "$src/install-vpn.sh"
    vpn_installed=yes
fi

if [ "$vpn_installed" = yes ] && ask "Enable VPN-to-LAN forwarding/NAT now? Choose Yes only after configuring the OpenVPN server and 10.8.0.0/24 VPN range; this changes firewall and IP-forwarding rules."; then
    install_packages iptables
    "$src/install-vpn-nat.sh"
fi

cat <<'DONE'

Guided setup finished. The shared approval service is active.
Enroll another account with: sudo thessley-pam enroll --user ACCOUNT
DONE
echo "Optional component uninstall scripts are in $src."

if [ "$ssh_installed" = yes ]; then
    echo "SSH module installed, but SSH/PAM configuration was not changed. Read $src/docs/SSH.md."
    echo "Before any SSH/PAM edit, arm: sudo $src/ssh-config-rollback.sh arm 10"
    echo "After a successful fresh SSH login, finalize with: sudo $src/ssh-config-rollback.sh cancel"
fi
if [ "$vpn_installed" = yes ]; then
    echo "OpenVPN approval hook installed. Configure certificates, public host, and ports using $src/docs/VPN.md."
fi
if [ "$admin_installed" = yes ]; then
    echo "Open Thessley Login from the applications menu."
fi
