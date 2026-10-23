#!/usr/bin/env bash
# Root entry point for updating the installed Thessley SSH policy and web UI code.
# The updater takes a timestamped backup and rolls back changed files if activation fails.
# It preserves sshd_config, /etc/pam.d/sshd, SSH grace settings, and service unit configuration.
set -Eeuo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo "Run as root: sudo bash $0" >&2
    exit 1
fi

src=$(cd -- "$(dirname -- "$0")" && pwd)
exec bash "$src/upgrade-ssh-user-controls.sh" "$@"
