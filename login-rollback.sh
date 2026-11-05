#!/usr/bin/env bash
# Timed rollback for the optional GNOME QR-login integration.
set -Eeuo pipefail

readonly STATE_DIR=/var/lib/thessley-login-rollback
readonly ACTIVE_BACKUP=$STATE_DIR/active-backup
readonly TIMER_NAME=thessley-login-rollback.timer
readonly SERVICE_NAME=thessley-login-rollback.service
readonly TIMER_PATH=/etc/systemd/system/$TIMER_NAME
readonly SERVICE_PATH=/etc/systemd/system/$SERVICE_NAME
readonly APP_PATHS=(
    /etc/pam.d/gdm-thessley
    /var/lib/thessley-pam/enrolled-users
    /usr/share/gnome-shell/extensions/thessley-passkey-login@eagleeye-intelligence.com
    /etc/gdm3/greeter.dconf-defaults
    /etc/gdm3/greeter.dconf-defaults.bak-thessley
    /usr/share/gdm/dconf/99-thessley-passkey-login
    /usr/share/gdm/dconf/99-thessley-passkey-login.bak-thessley-admin
    /var/lib/gdm3/greeter-dconf-defaults
    /usr/local/sbin/thessley-install-rollback
    /usr/local/lib/thessley-pam/thessley_pam/admin_helper.py
    /usr/local/lib/thessley-pam/thessley_pam/admin_gui.py
)

die() { printf 'Thessley login rollback: %s\n' "$*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die 'run with sudo.'

key_for() { printf '%s' "$1" | sed 's#^/##; s#/#__#g'; }

validate_backup() {
    local backup=$1 path key state
    [[ -n $backup ]] || die 'missing snapshot path.'
    backup=$(realpath -e -- "$backup") || die 'snapshot path does not exist.'
    [[ $(dirname -- "$backup") == /var/backups && $(basename -- "$backup") == thessley-pam-login-before-* ]] \
        || die 'snapshot must be a Thessley login backup directly under /var/backups.'
    [[ -d $backup && ! -L $backup && $(stat -c %u "$backup") == 0 ]] || die 'snapshot must be a root-owned directory.'
    for path in "${APP_PATHS[@]}"; do
        key=$(key_for "$path")
        state=$(cat "$backup/$key.state" 2>/dev/null || true)
        [[ $state == present || $state == absent ]] || die "snapshot is incomplete: $key.state is missing or invalid."
    done
    printf '%s\n' "$backup"
}

assert_clear() {
    if systemctl is-active --quiet "$TIMER_NAME" || [[ -e $TIMER_PATH || -e $SERVICE_PATH || -e $ACTIVE_BACKUP ]]; then
        die 'a login rollback is already pending; approve it or let it expire before reinstalling.'
    fi
}

clear_timer() {
    systemctl disable --now "$TIMER_NAME" >/dev/null 2>&1 || true
    rm -f -- "$TIMER_PATH" "$SERVICE_PATH"
    systemctl daemon-reload
    rm -f -- "$ACTIVE_BACKUP"
}

snapshot() {
    local backup path key
    assert_clear
    backup=$(mktemp -d "/var/backups/thessley-pam-login-before-$(date -u +%Y%m%dT%H%M%SZ).XXXXXX")
    chown root:root "$backup"
    chmod 0700 "$backup"
    for path in "${APP_PATHS[@]}"; do
        key=$(key_for "$path")
        if [[ -e $path || -L $path ]]; then
            cp -a --parents "$path" "$backup/"
            printf 'present\n' > "$backup/$key.state"
        else
            printf 'absent\n' > "$backup/$key.state"
        fi
        chmod 0600 "$backup/$key.state"
    done
    printf '%s\n' "$backup"
}

arm() {
    local backup=$1 minutes=${2:-60} next
    [[ $minutes =~ ^[0-9]+$ ]] && (( minutes >= 10 && minutes <= 180 )) \
        || die 'choose a rollback delay from 10 to 180 minutes.'
    assert_clear
    backup=$(validate_backup "$backup")
    install -d -o root -g root -m 0700 "$STATE_DIR"
    printf '%s\n' "$backup" > "$ACTIVE_BACKUP"
    chmod 0600 "$ACTIVE_BACKUP"
    cat > "$SERVICE_PATH" <<'UNIT'
[Unit]
Description=Restore the previous Thessley GNOME QR-login configuration

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/thessley-login-rollback restore
UNIT
    cat > "$TIMER_PATH" <<UNIT
[Unit]
Description=Timed Thessley GNOME QR-login test rollback

[Timer]
OnActiveSec=${minutes}min
AccuracySec=1s
Unit=$SERVICE_NAME

[Install]
WantedBy=timers.target
UNIT
    chmod 0644 "$SERVICE_PATH" "$TIMER_PATH"
    systemctl daemon-reload
    if ! systemctl enable --now "$TIMER_NAME" || ! systemctl is-active --quiet "$TIMER_NAME"; then
        clear_timer
        die 'systemd could not activate the GNOME login rollback timer.'
    fi
    next=$(systemctl show "$TIMER_NAME" --property=NextElapseUSecMonotonic --value)
    if [[ -z $next || $next == n/a || $next == 0 ]]; then
        clear_timer
        die 'systemd reports no scheduled GNOME login rollback.'
    fi
    printf 'GNOME QR-login rollback is armed for %s minutes; its countdown restarts after reboot. Approve after testing the boot-time greeter QR.\n' "$minutes"
}

restore() {
    local backup=${1:-} path key state failed=0
    if [[ -z $backup ]]; then
        [[ -r $ACTIVE_BACKUP ]] || die 'no GNOME login snapshot is recorded.'
        backup=$(cat "$ACTIVE_BACKUP")
    fi
    backup=$(validate_backup "$backup")
    for path in "${APP_PATHS[@]}"; do
        key=$(key_for "$path")
        state=$(cat "$backup/$key.state")
        rm -rf -- "$path" || { printf 'Could not remove %s\n' "$path" >&2; failed=1; continue; }
        if [[ $state == present ]]; then
            install -d -o root -g root -m 0755 "$(dirname -- "$path")" || { failed=1; continue; }
            cp -a -- "$backup/${path#/}" "$path" || { printf 'Could not restore %s\n' "$path" >&2; failed=1; }
        fi
    done
    if [[ -x /usr/share/gdm/generate-config ]]; then
        /usr/share/gdm/generate-config || { echo 'Could not regenerate GDM configuration.' >&2; failed=1; }
    fi
    if (( failed )); then
        logger -t thessley-login-rollback "restore incomplete; snapshot retained at $backup"
        die "restore incomplete. Snapshot retained at $backup."
    fi
    clear_timer
    logger -t thessley-login-rollback "restored GDM QR-login files from $backup"
    printf 'Previous GNOME QR-login configuration restored. Password fallback is unchanged. Snapshot retained at %s\n' "$backup"
}

approve() {
    if ! systemctl is-active --quiet "$TIMER_NAME" && [[ ! -r $ACTIVE_BACKUP ]]; then
        die 'no GNOME login rollback is pending.'
    fi
    local backup=''
    [[ ! -r $ACTIVE_BACKUP ]] || backup=$(cat "$ACTIVE_BACKUP")
    clear_timer
    logger -t thessley-login-rollback 'GNOME QR-login test approved; automatic rollback stopped'
    printf 'GNOME QR-login test approved. Automatic rollback stopped; snapshot retained%s.\n' \
        "${backup:+ at $backup}"
}

status() {
    if systemctl is-active --quiet "$TIMER_NAME"; then
        systemctl list-timers --all --no-legend "$TIMER_NAME"
        [[ ! -r $ACTIVE_BACKUP ]] || printf 'Pre-test snapshot: %s\n' "$(cat "$ACTIVE_BACKUP")"
        echo 'GNOME QR-login test is awaiting approval.'
    elif [[ -e $TIMER_PATH || -e $SERVICE_PATH || -e $ACTIVE_BACKUP ]]; then
        echo 'GNOME login rollback needs attention: timer is not active.'
        [[ ! -r $ACTIVE_BACKUP ]] || printf 'Pre-test snapshot: %s\n' "$(cat "$ACTIVE_BACKUP")"
    else
        echo 'No GNOME login rollback is pending.'
    fi
}

case "${1:-status}" in
    snapshot) [[ $# -eq 1 ]] || die 'usage: login-rollback.sh snapshot'; snapshot ;;
    arm) [[ $# -ge 2 && $# -le 3 ]] || die 'usage: login-rollback.sh arm SNAPSHOT [MINUTES]'; arm "$2" "${3:-60}" ;;
    restore) [[ $# -le 2 ]] || die 'usage: login-rollback.sh restore [SNAPSHOT]'; restore "${2:-}" ;;
    approve) [[ $# -eq 1 ]] || die 'usage: login-rollback.sh approve'; approve ;;
    status) [[ $# -eq 1 ]] || die 'usage: login-rollback.sh status'; status ;;
    assert-clear) [[ $# -eq 1 ]] || die 'usage: login-rollback.sh assert-clear'; assert_clear ;;
    *) die 'use snapshot, arm, restore, approve, status, or assert-clear.' ;;
esac
