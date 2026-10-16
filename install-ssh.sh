#!/bin/sh
# Builds and installs pam_thessley_phone.so, the phone step for ssh (sshd shows PAM text only together with a
# question, so the module shows the QR code with "Approve on your phone, then press Enter"). Run after install.sh.
#
#   sudo ./install-ssh.sh
#
# It does NOT edit sshd_config or /etc/pam.d/sshd. For "ssh key + phone once, then the key alone for 4 hours":
#
#   sudo groupadd thessley-ssh;  sudo usermod -aG thessley-ssh USER          who is affected
#   sudo thessley-pam enroll --user USER                                     their phone
#   sudo thessley-pam grace --service sshd --hours 4                         the pass
#   sudo thessley-pam require --service sshd on                              refuse members who have no phone
#
#   /etc/ssh/sshd_config (end of the file):
#       Match Group thessley-ssh
#           AuthenticationMethods publickey,keyboard-interactive:pam
#           KbdInteractiveAuthentication yes
#
#   /etc/pam.d/sshd (before "@include common-auth"):
#       auth  [success=ignore default=1]  pam_succeed_if.so quiet user ingroup thessley-ssh
#       auth  [success=done default=die]  pam_thessley_phone.so
#   and, before "@include common-session" (optional; prints the "approved earlier" note once for shell logins):
#       session  optional  pam_thessley_phone.so
#
# then: sudo sshd -t && sudo systemctl reload ssh
set -eu

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
