#!/bin/sh
# Put the GNOME login-screen enrollment marker in public-readable persistent
# state. Services protect /etc as read-only; /var/lib is the proper location
# for this marker and supports atomic replacement.
set -eu

[ "$(id -u)" = 0 ] || { echo "Run with sudo." >&2; exit 1; }

state_dir=/var/lib/thessley-pam
target=$state_dir/enrolled-users
legacy=/etc/thessley-pam-enrolled
install -d -o root -g root -m 0755 "$state_dir"

if [ -L "$target" ] || { [ -e "$target" ] && [ ! -f "$target" ]; }; then
    echo "Refusing unsafe enrolled-user marker path: $target" >&2
    exit 1
fi
if [ ! -e "$target" ]; then
    install -o root -g root -m 0644 /dev/null "$target"
else
    chown root:root "$target"
    chmod 0644 "$target"
fi

if [ -L "$legacy" ]; then
    link=$(readlink -- "$legacy")
    [ "$link" = "$target" ] || {
        echo "Refusing unexpected legacy enrolled-user symlink: $legacy -> $link" >&2
        exit 1
    }
elif [ -e "$legacy" ]; then
    [ -f "$legacy" ] || { echo "Refusing unsafe legacy enrolled-user path: $legacy" >&2; exit 1; }
    if [ ! -s "$target" ] && [ -s "$legacy" ]; then
        install -o root -g root -m 0644 "$legacy" "$target"
    fi
    rm -f -- "$legacy"
    ln -s "$target" "$legacy"
else
    ln -s "$target" "$legacy"
fi

echo "Enrolled-user marker is ready at $target."
