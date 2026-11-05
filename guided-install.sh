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

ask_yes_default() {
    while :; do
        printf '%s [Y/n] ' "$1" > /dev/tty
        IFS= read -r answer < /dev/tty || return 1
        case "$answer" in
            ''|y|Y|yes|YES|Yes) return 0 ;;
            n|N|no|NO|No) return 1 ;;
            *) echo "Please answer y or n." > /dev/tty ;;
        esac
    done
}

install_packages() {
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@"
}

enable_vpn_lan_forwarding() {
    vpn_subnet=${1:-}
    if [ -z "$vpn_subnet" ] && [ -r /etc/openvpn/server/thessley.conf ]; then
        vpn_subnet=$(awk '$1 == "server" && $3 == "255.255.255.0" { print $2 "/24"; exit }' /etc/openvpn/server/thessley.conf)
    fi
    if [ -z "$vpn_subnet" ]; then
        printf 'VPN tunnel subnet to forward [10.8.0.0/24]: ' > /dev/tty
        IFS= read -r vpn_subnet < /dev/tty || vpn_subnet=10.8.0.0/24
        vpn_subnet=${vpn_subnet:-10.8.0.0/24}
    fi
    install_packages iptables
    VPN_SUBNET="$vpn_subnet" "$src/install-vpn-nat.sh"
}

cat <<'INTRO'
Thessley guided setup

The shared phone-approval service is required. The HTTPS web admin page is
enabled by default; answer n to skip it. Other optional features default to
No. This installer does not modify existing sshd_config,
PAM login stacks, or OpenVPN server configuration. The separate OpenVPN
server option creates a new, isolated Thessley instance only when one is not
already installed. An existing Thessley server and its CA/client keys are
preserved. Selecting a LAN route enables VPN-to-LAN forwarding/NAT automatically; enter `none` to skip the route.
The GNOME option creates its own password-preserving PAM service and does not
replace the normal password login.
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

if ask_yes_default "Install and enable the HTTPS web admin page on its configured address and TCP port 47820?"; then
    "$src/install-web.sh"
    /usr/local/sbin/thessley-pam web on
    /usr/local/sbin/thessley-pam web status
    echo "Restrict TCP port 47820 to trusted networks in your firewall."
fi

admin_installed=no
if ask "Install the Thessley Login desktop admin app (GTK/libadwaita required)?"; then
    desktop_packages="python3-gi gir1.2-adw-1"
    if ! command -v pkexec >/dev/null 2>&1; then
        # Ubuntu releases that split PolicyKit no longer publish policykit-1;
        # pkexec is the command this app needs and pulls in its daemon.
        if apt-cache policy pkexec 2>/dev/null | grep -Eq 'Candidate: [^ (]'; then
            desktop_packages="$desktop_packages pkexec"
        elif apt-cache policy policykit-1 2>/dev/null | grep -Eq 'Candidate: [^ (]'; then
            desktop_packages="$desktop_packages policykit-1"
        else
            echo "Cannot find an installable package that provides pkexec. Install PolicyKit from your OS repositories, then rerun this option." >&2
            exit 1
        fi
    fi
    # Intentional word splitting: these are fixed apt package names above.
    # shellcheck disable=SC2086
    install_packages $desktop_packages
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
if ask "Install QR approval on the GNOME login screen? Password fallback stays enabled by default; QR-only is an opt-in admin setting."; then
    if [ ! -x /usr/share/gdm/generate-config ] \
        || { [ ! -d /usr/share/gdm/dconf ] && [ ! -f /etc/gdm3/greeter.dconf-defaults ]; }; then
        echo "GDM configuration is not present; skipping GNOME login integration."
    else
        "$src/install-login.sh"
        login_installed=yes
        if [ "$admin_installed" = yes ]; then
            echo "Password fallback is still enabled. Test QR login first; only then consider QR-only in the Thessley Login admin app."
            echo "To restore password fallback and remove QR login later: sudo ./uninstall-login.sh"
        else
            echo "Password fallback remains enabled. Install the admin app separately if you want the optional QR-only setting."
        fi
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
vpn_server_installed=no
if [ -e /etc/openvpn/server/thessley.conf ]; then
    if systemctl is-active --quiet thessley-pam-vpn.service; then
        echo "Existing Thessley OpenVPN server and QR-approval service detected. Preserving its configuration, CA, and client keys; no new VPN setup is needed."
        if grep -q '^push "route ' /etc/openvpn/server/thessley.conf; then
            if systemctl is-active --quiet thessley-pam-vpn-nat.service && systemctl is-enabled --quiet thessley-pam-vpn-nat.service; then
                echo "VPN-to-LAN forwarding/NAT is already active and enabled."
            elif ask_yes_default "Enable VPN-to-LAN forwarding/NAT for the configured LAN route? This lets approved VPN clients reach that LAN and adjusts firewall/IP forwarding."; then
                enable_vpn_lan_forwarding
            else
                echo "VPN-to-LAN forwarding/NAT was skipped; clients can reach this VPN server only."
            fi
        else
            echo "No LAN route is configured in the existing VPN server; forwarding was not changed."
        fi
    elif ask "Existing Thessley OpenVPN config found but its approval service is not active. Install or repair the QR-approval hook? This preserves the server config and keys."; then
        install_packages openvpn easy-rsa
        "$src/install-vpn.sh"
        vpn_installed=yes
    else
        echo "Existing Thessley OpenVPN config preserved. No VPN files were changed."
    fi
elif ask "Install a new OpenVPN server with Thessley QR approval? It detects the private LAN route, preserves existing VPN configs, and adds only its required UFW ports if UFW is active."; then
    THESSLEY_GUIDED_VPN_APPROVED=1 bash "$src/install-openvpn-server.sh"
    vpn_installed=yes
    vpn_server_installed=yes
elif ask "Install the Thessley QR-approval hook for an existing OpenVPN server? This does not configure or start OpenVPN."; then
    install_packages openvpn easy-rsa
    "$src/install-vpn.sh"
    vpn_installed=yes
fi

if [ "$vpn_installed" = yes ]; then
    if [ "$vpn_server_installed" = yes ] && ! grep -q '^push "route ' /etc/openvpn/server/thessley.conf; then
        echo "No LAN route was selected for this new VPN server; skipping VPN-to-LAN forwarding."
    elif [ "$vpn_server_installed" = yes ]; then
        echo "Enabling VPN-to-LAN forwarding/NAT for the route selected during VPN setup."
        enable_vpn_lan_forwarding
    elif ask_yes_default "Enable VPN-to-LAN forwarding/NAT now? This lets VPN clients reach the configured LAN route and changes firewall/IP-forwarding rules."; then
        enable_vpn_lan_forwarding
    else
        echo "VPN-to-LAN forwarding/NAT was skipped; clients can reach this VPN server only."
    fi
fi

cat <<'DONE'

Guided setup finished. The shared approval service is active.
Enroll another account with: sudo thessley-pam enroll --user ACCOUNT
After verifying phone approval and the web admin page, approve this installation in Admin or run:
  sudo thessley-install-rollback approve
DONE
echo "Optional component uninstall scripts are in $src."

if [ "$ssh_installed" = yes ]; then
    echo "SSH module installed, but SSH/PAM configuration was not changed. Read $src/docs/SSH.md."
    echo "Before any SSH/PAM edit, arm: sudo $src/ssh-config-rollback.sh arm 10"
    echo "After a successful fresh SSH login, finalize with: sudo $src/ssh-config-rollback.sh cancel"
fi
if [ "$vpn_installed" = yes ]; then
    echo "OpenVPN setup details: $src/docs/VPN.md. Router port forwarding is still required for remote access."
fi
if [ "$admin_installed" = yes ]; then
    echo "Open Thessley Login from the applications menu."
fi
