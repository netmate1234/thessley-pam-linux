#!/usr/bin/env bash
# Timed rollback for the core Thessley approval-service installation.
set -Eeuo pipefail

readonly STATE_DIR=/var/lib/thessley-setup-rollback
readonly ACTIVE_BACKUP=$STATE_DIR/active-backup
readonly TIMER_NAME=thessley-setup-rollback.timer
readonly SERVICE_NAME=thessley-setup-rollback.service
readonly TIMER_PATH=/etc/systemd/system/$TIMER_NAME
readonly SERVICE_PATH=/etc/systemd/system/$SERVICE_NAME
readonly APP_PATHS=(
    /usr/local/lib/thessley-pam
    /usr/local/sbin/thessley-pam
    /etc/systemd/system/thessley-pam-approvals.service
    /usr/local/sbin/thessley-ssh-config-rollback
)

die() { printf 'Thessley setup rollback: %s\n' "$*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die 'run with sudo.'

clear_timer() {
    systemctl disable --now "$TIMER_NAME" >/dev/null 2>&1 || true
    rm -f -- "$TIMER_PATH" "$SERVICE_PATH"
    systemctl daemon-reload
    rm -f -- "$ACTIVE_BACKUP"
}

validate_backup() {
    local backup=$1 key
    [[ -n $backup ]] || die 'missing backup path.'
    backup=$(realpath -e -- "$backup") || die 'backup path does not exist.'
    [[ $(dirname -- "$backup") == /var/backups && $(basename -- "$backup") == thessley-pam-install-* ]] \
        || die 'backup must be a Thessley installer backup directly under /var/backups.'
    [[ -d $backup && ! -L $backup && $(stat -c %u "$backup") == 0 ]] \
        || die 'backup must be a root-owned directory.'
    for path in "${APP_PATHS[@]}"; do
        key=$(printf '%s' "$path" | sed 's#^/##; s#/#__#g')
        [[ $(cat "$backup/$key.state" 2>/dev/null || true) == present || $(cat "$backup/$key.state" 2>/dev/null || true) == absent ]] \
            || die "backup is incomplete: $key.state is missing or invalid."
    done
    printf '%s\n' "$backup"
}

assert_clear() {
    if systemctl is-active --quiet "$TIMER_NAME" || [[ -e $TIMER_PATH || -e $SERVICE_PATH || -e $ACTIVE_BACKUP ]]; then
        die 'an installation rollback is already pending. Approve it in Thessley Admin or let it expire before installing again.'
    fi
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
Description=Restore the previous Thessley approval-service installation

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/thessley-install-rollback restore
UNIT
    cat > "$TIMER_PATH" <<UNIT
[Unit]
Description=Timed Thessley installation approval

[Timer]
OnActiveSec=${minutes}min
AccuracySec=1s
Unit=$SERVICE_NAME

[Install]
WantedBy=timers.target
UNIT
    chmod 0644 "$SERVICE_PATH" "$TIMER_PATH"
    systemctl daemon-reload
    if ! systemctl enable --now "$TIMER_NAME"; then
        clear_timer
        die 'systemd could not activate the installation timer.'
    fi
    if ! systemctl is-active --quiet "$TIMER_NAME"; then
        clear_timer
        die 'systemd did not activate the installation timer.'
    fi
    next=$(systemctl show "$TIMER_NAME" --property=NextElapseUSecMonotonic --value)
    if [[ -z $next || $next == n/a || $next == 0 ]]; then
        clear_timer
        die 'systemd reports no scheduled installation rollback.'
    fi
    printf 'Installation approval timer is armed for %s minutes. After a reboot, its countdown restarts. Approve the installation in Thessley Admin after verifying it.\n' "$minutes"
}

restore() {
    local backup path key state failed=0
    [[ -r $ACTIVE_BACKUP ]] || die 'no installation snapshot is recorded.'
    backup=$(validate_backup "$(cat "$ACTIVE_BACKUP")")
    systemctl stop thessley-pam-approvals.service >/dev/null 2>&1 || true
    for path in "${APP_PATHS[@]}"; do
        key=$(printf '%s' "$path" | sed 's#^/##; s#/#__#g')
        state=$(cat "$backup/$key.state")
        rm -rf -- "$path" || { printf 'Could not remove %s\n' "$path" >&2; failed=1; continue; }
        if [[ $state == present ]]; then
            install -d -o root -g root -m 0755 "$(dirname -- "$path")" || { failed=1; continue; }
            cp -a -- "$backup/${path#/}" "$path" || { printf 'Could not restore %s\n' "$path" >&2; failed=1; }
        fi
    done
    systemctl daemon-reload || failed=1
    if [[ $(cat "$backup/service-enabled.state") == enabled ]]; then
        systemctl enable thessley-pam-approvals.service || failed=1
    else
        systemctl disable thessley-pam-approvals.service || failed=1
    fi
    if [[ $(cat "$backup/service-active.state") == active ]]; then
        systemctl restart thessley-pam-approvals.service || failed=1
    else
        systemctl stop thessley-pam-approvals.service || failed=1
    fi
    if (( failed )); then
        logger -t thessley-setup-rollback 'restore incomplete; snapshot retained for manual recovery'
        die "restore incomplete. Snapshot retained at $backup."
    fi
    clear_timer
    logger -t thessley-setup-rollback "restored previous app files from $backup"
    printf 'The previous Thessley approval-service installation was restored. Snapshot retained at %s\n' "$backup"
}

status() {
    if systemctl is-active --quiet "$TIMER_NAME"; then
        [[ -r $ACTIVE_BACKUP ]] || { echo 'Installation rollback needs attention: its snapshot record is missing.'; return 0; }
        systemctl list-timers --all --no-legend "$TIMER_NAME"
        [[ -r $ACTIVE_BACKUP ]] && printf 'Pre-install snapshot: %s\n' "$(cat "$ACTIVE_BACKUP")"
        echo 'This installation is awaiting approval.'
    elif [[ -e $TIMER_PATH || -e $SERVICE_PATH || -e $ACTIVE_BACKUP ]]; then
        echo 'Installation rollback needs attention: the timer is not active.'
        [[ -r $ACTIVE_BACKUP ]] && printf 'Pre-install snapshot: %s\n' "$(cat "$ACTIVE_BACKUP")"
    else
        echo 'No installation is awaiting approval.'
    fi
}

approve() {
    if ! systemctl is-active --quiet "$TIMER_NAME" && [[ ! -r $ACTIVE_BACKUP ]]; then
        die 'no installation approval is pending.'
    fi
    clear_timer
    logger -t thessley-setup-rollback 'installation approved by administrator; automatic rollback stopped'
    echo 'Installation approved. Automatic rollback stopped; pre-install snapshot retained in /var/backups.'
}

case "${1:-status}" in
    assert-clear) assert_clear ;;
    arm) [[ $# -ge 2 && $# -le 3 ]] || die 'usage: setup-rollback.sh arm BACKUP [MINUTES]'; arm "$2" "${3:-60}" ;;
    restore) restore ;;
    status) status ;;
    approve) approve ;;
    *) die 'use assert-clear, arm, restore, status, or approve.' ;;
esac
