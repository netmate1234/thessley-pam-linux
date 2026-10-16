#!/bin/sh
# Lets any user add their OWN first phone, without being an administrator:
#
#   sudo ./install-selfenroll.sh                  (once, as an administrator)
#   sudo thessley-pam enroll-me                   (then, as that user, in a terminal)
#
# It adds one file to /etc/sudoers.d that lets everyone run exactly "thessley-pam enroll-me" (and "... enroll-me
# --link") as root, without a password. That command takes the account from sudo (SUDO_USER, which the caller cannot
# choose), so nobody can add a phone for another account; it only ever adds the FIRST phone of an account (a second one,
# or a replacement for switched-off phones, needs an administrator: sudo thessley-pam enroll --user NAME).
#
# Trade-off: whoever can run a session as that account (it takes its password) can enrol their own phone first. Switch
# it off any time with:   sudo thessley-pam self-enroll off     (on again: self-enroll on)
# Undo completely:         sudo ./uninstall-selfenroll.sh
set -eu

[ "$(id -u)" = 0 ] || { echo "Run with sudo." >&2; exit 1; }
[ -x /usr/local/sbin/thessley-pam ] || { echo "Run install.sh first." >&2; exit 1; }
command -v visudo >/dev/null || { echo "Missing visudo (the sudo package)." >&2; exit 1; }

target=/etc/sudoers.d/thessley-pam-enroll-me
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
cat > "$tmp" <<'SUDOERS'
# Added by thessley-pam install-selfenroll.sh. Any user may add their own first phone; see that script.
ALL ALL=(root) NOPASSWD: /usr/local/sbin/thessley-pam enroll-me, /usr/local/sbin/thessley-pam enroll-me --link
SUDOERS
visudo -cf "$tmp" >/dev/null || { echo "The sudoers line did not validate; nothing was installed." >&2; exit 1; }
install -o root -g root -m 0440 "$tmp" "$target"
visudo -c >/dev/null || { rm -f "$target"; echo "sudoers became invalid; removed the new file." >&2; exit 1; }
echo "Installed $target."
echo "A user now adds their own first phone with:  sudo thessley-pam enroll-me"
echo "Switch it off:  sudo thessley-pam self-enroll off"
