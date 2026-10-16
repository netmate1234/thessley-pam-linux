#!/bin/sh
# Undo install-selfenroll.sh: users can no longer run "thessley-pam enroll-me" without being administrators.
set -eu
[ "$(id -u)" = 0 ] || { echo "Run with sudo." >&2; exit 1; }
rm -f /etc/sudoers.d/thessley-pam-enroll-me
echo "Removed /etc/sudoers.d/thessley-pam-enroll-me."
