#!/bin/sh
# Builds and installs pam_thessley_phone.so, the phone step for ssh. install.sh installs and starts the shared HTTPS
# approval listener; keyboard-interactive SSH clients display its QR informational text without requiring Enter.
#
#   sudo ./install-ssh.sh                       build and install the PAM module only
#   sudo ./install-ssh.sh --configure-sshd      also write the sshd Match block (keeps any admin exemption working)
#
# --configure-sshd writes /etc/ssh/sshd_config.d/10-thessley-ssh-gate.conf instead of appending to the end of
# /etc/ssh/sshd_config. sshd keeps the first value it sees, and sshd_config.d/*.conf is Included near the top of
# sshd_config, so an address exemption in a drop-in (for example 50-hypervisor-key-only.conf) silently beat a block
# appended at the end. An exemption now has to use a lower file number than 10 to win, which is visible in
# `ls /etc/ssh/sshd_config.d`. The block is still last in its own file, as a Match block must be.
#
# For "ssh key + phone once, then the key alone for 4 hours":
#
#   sudo groupadd thessley-ssh;  sudo usermod -aG thessley-ssh USER          who is affected
#   sudo thessley-pam enroll --user USER                                     their phone
#   sudo thessley-pam grace --service sshd --hours 4                         the pass
#   sudo thessley-pam require --service sshd on                              refuse members who have no phone
#
#   (install-ssh.sh --configure-sshd writes this, using the group given with --group)
#       Match Group thessley-ssh
#           AuthenticationMethods publickey,keyboard-interactive:pam keyboard-interactive:pam
#           KbdInteractiveAuthentication yes
#
#   /etc/pam.d/sshd (before "@include common-auth"):
#       auth  [success=ignore default=1]  pam_succeed_if.so quiet user ingroup thessley-ssh
#       auth  [success=done auth_err=ignore default=die]  pam_thessley_phone.so
#   and, before "@include common-session" (optional; prints the "approved earlier" note once for shell logins):
#       session  optional  pam_thessley_phone.so
#
# then: sudo sshd -t && sudo systemctl reload ssh
set -eu

group=thessley-ssh
configure_sshd=0
usage() {
    cat <<'EOF'
usage: install-ssh.sh [--configure-sshd] [--group NAME]

  --configure-sshd   write /etc/ssh/sshd_config.d/10-thessley-ssh-gate.conf,
                     validate it with sshd -t, and reload ssh
  --group NAME       group whose members need the phone step (default: thessley-ssh)
EOF
}
while [ $# -gt 0 ]; do
    case "$1" in
        --configure-sshd) configure_sshd=1 ;;
        -g|--group) shift; [ $# -gt 0 ] || { echo "--group needs a name." >&2; exit 2; }; group=$1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done
case "$group" in
    ''|*[!a-z0-9_-]*|[!a-z_]*) echo "Invalid group name: $group" >&2; exit 2 ;;
esac

[ "$(id -u)" = 0 ] || { echo "Run with sudo." >&2; exit 1; }
[ -x /usr/local/lib/thessley-pam/pam-helper ] || { echo "Run install.sh first." >&2; exit 1; }
command -v gcc >/dev/null || { echo "Missing gcc: sudo apt install build-essential" >&2; exit 1; }
[ -f /usr/include/security/pam_modules.h ] || { echo "Missing PAM headers: sudo apt install libpam0g-dev" >&2; exit 1; }

src=$(cd "$(dirname "$0")" && pwd)
secdir=$(dirname "$(find /lib /usr/lib -name pam_unix.so 2>/dev/null | head -n1)")
[ -d "$secdir" ] || { echo "Cannot find the PAM module directory." >&2; exit 1; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
gcc -Wall -Wextra -Werror -O2 -fPIC -shared -o "$tmp/pam_thessley_phone.so" "$src/pam-module/pam_thessley_phone.c" -lpam
install -o root -g root -m 0644 "$tmp/pam_thessley_phone.so" "$secdir/pam_thessley_phone.so"
echo "Installed pam_thessley_phone.so in $secdir."

if [ "$configure_sshd" = 1 ]; then
    dropin_dir=/etc/ssh/sshd_config.d
    gate=$dropin_dir/10-thessley-ssh-gate.conf
    [ -d "$dropin_dir" ] || { echo "$dropin_dir does not exist; configure sshd by hand." >&2; exit 1; }
    grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config || {
        echo "/etc/ssh/sshd_config does not Include sshd_config.d; configure sshd by hand." >&2
        exit 1
    }
    getent group "$group" >/dev/null || groupadd "$group"
    old=$(mktemp)
    had_old=0
    if [ -e "$gate" ]; then cp -a "$gate" "$old"; had_old=1; fi
    trap 'rm -rf "$tmp" "$old"' EXIT

    cat > "$gate" <<EOF
# Thessley SSH gate: members of $group prove their SSH key and a phone approval.
# Written by install-ssh.sh --configure-sshd. Last block in this file, as Match must be.
# sshd keeps the first AuthenticationMethods it sees, so an exemption meant to win goes in an
# earlier drop-in (a lower number), for example 05-admin-exemption.conf.
Match Group $group
    AuthenticationMethods publickey,keyboard-interactive:pam keyboard-interactive:pam
    KbdInteractiveAuthentication yes
EOF
    chown root:root "$gate"
    chmod 0644 "$gate"

    if ! sshd -t; then
        if [ "$had_old" = 1 ]; then mv "$old" "$gate"; else rm -f "$gate"; fi
        echo "sshd refused the new configuration; no change was kept." >&2
        exit 1
    fi
    if systemctl reload ssh 2>/dev/null; then :; elif systemctl reload sshd 2>/dev/null; then :; else
        echo "Could not reload ssh; run: sudo systemctl reload ssh" >&2
    fi
    echo "Wrote $gate for group $group and reloaded ssh."

    for other in "$dropin_dir"/*.conf; do
        [ -f "$other" ] || continue
        [ "$other" = "$gate" ] && continue
        base=$(basename "$other")
        first=$(printf '%s\n%s\n' "$(basename "$gate")" "$base" | LC_ALL=C sort | head -n1)
        [ "$first" = "$base" ] || continue
        if grep -Eq '^[[:space:]]*AuthenticationMethods' "$other"; then
            echo "Note: $base is read before the gate and sets AuthenticationMethods; it wins for the users it matches."
        fi
    done
    if grep -Eq "^[[:space:]]*Match[[:space:]]+Group[[:space:]]+$group([[:space:]]|$)" /etc/ssh/sshd_config; then
        echo "Note: /etc/ssh/sshd_config still has a Match Group $group block at its end; it is redundant now."
    fi
fi

