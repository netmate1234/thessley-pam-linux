#!/usr/bin/env bash
# Persistent, one-shot rollback for SSH/PAM login policy changes.
# The calendar timer survives a reboot; the snapshot and this helper are root-only.
set -Eeuo pipefail

readonly SCRIPT_PATH=/usr/local/sbin/thessley-ssh-config-rollback
readonly UNIT_DIR=/etc/systemd/system
readonly TIMER_NAME=thessley-ssh-config-rollback.timer
readonly SERVICE_NAME=thessley-ssh-config-rollback.service
readonly TIMER_PATH=$UNIT_DIR/$TIMER_NAME
readonly SERVICE_PATH=$UNIT_DIR/$SERVICE_NAME
readonly STATE_DIR=/var/lib/thessley-ssh-config-rollback
readonly ACTIVE_BACKUP=$STATE_DIR/active-backup
readonly -a SNAPSHOT_PATHS=(
    /etc/ssh/sshd_config
    /etc/ssh/sshd_config.d
    /etc/pam.d/sshd
    /etc/thessley-pam/ssh-login-mode
    /etc/thessley-pam/ssh-policy-failure
    /etc/thessley-pam/ssh-users
    /etc/thessley-pam/config.json
    /etc/ssh/sshd_config.d/90-thessley-deny-users.conf
)

die() { echo "Thessley SSH rollback: $*" >&2; exit 1; }

require_root() {
    [[ ${EUID:-$(id -u)} -eq 0 ]] || die "run with sudo: sudo $0 arm 10"
}

cleanup_units() {
    systemctl disable --now "$TIMER_NAME" >/dev/null 2>&1 || true
    rm -f -- "$TIMER_PATH" "$SERVICE_PATH"
    systemctl daemon-reload || true
}

snapshot_one() {
    local backup=$1 path=$2 key target
    key=${path#/}
    target=$backup/files/$key
    install -d -o root -g root -m 0700 "$(dirname -- "$backup/$key")" "$(dirname -- "$target")"
    if [[ -e $path || -L $path ]]; then
        printf 'present\n' > "$backup/$key.present"
        cp -a -- "$path" "$target"
    else
        printf 'absent\n' > "$backup/$key.absent"
    fi
}

restore_one() {
    local backup=$1 path=$2 key staged
    key=${path#/}
    if [[ -f $backup/$key.absent ]]; then
        rm -rf -- "$path"
        return
    fi
    [[ -e $backup/files/$key || -L $backup/files/$key ]] || {
        echo "Snapshot is incomplete for $path" >&2
        return 1
    }
    mkdir -p -- "$(dirname -- "$path")"
    staged="$(dirname -- "$path")/.thessley-restore.$(basename -- "$path").$$"
    rm -rf -- "$staged"
    cp -a -- "$backup/files/$key" "$staged"
    rm -rf -- "$path"
    mv -T -- "$staged" "$path"
}

arm_cleanup() {
    local rc=$?
    trap - EXIT
    if (( rc != 0 && ! armed )); then
        cleanup_units
        rm -f -- "$ACTIVE_BACKUP"
        echo "Rollback timer setup failed. SSH/PAM files were not changed. Keep the snapshot at $backup" >&2
    fi
    exit "$rc"
}

arm() {
    local minutes=${1:-} now deadline_epoch deadline deadline_utc next next_epoch ssh_service
    [[ $minutes =~ ^[0-9]+$ ]] && (( minutes >= 5 && minutes <= 60 )) \
        || die 'choose a rollback delay from 5 to 60 minutes.'
    command -v systemd-analyze >/dev/null || die 'systemd-analyze is required.'
    command -v sshd >/dev/null || die 'OpenSSH server is not installed.'
    systemctl is-active --quiet ssh && ssh_service=ssh \
        || { systemctl is-active --quiet sshd && ssh_service=sshd \
             || die 'Neither the ssh nor sshd service is active; refusing to arm a login rollback.'; }
    sshd -t || die 'Current SSH configuration is invalid; fix it before arming a change.'
    if [[ -e $TIMER_PATH || -e $SERVICE_PATH ]] || systemctl is-active --quiet "$TIMER_NAME"; then
        die "a rollback is already pending. Check with: systemctl list-timers $TIMER_NAME"
    fi

    local source_path
    source_path=$(readlink -f -- "$0") || die 'cannot resolve the rollback helper path.'
    if [[ $source_path != "$SCRIPT_PATH" ]]; then
        install -d -o root -g root -m 0755 "$(dirname -- "$SCRIPT_PATH")"
        install -o root -g root -m 0755 "$source_path" "$SCRIPT_PATH"
    fi

    backup=$(mktemp -d "/var/backups/thessley-ssh-config-rollback-$(date +%Y%m%d-%H%M%S).XXXXXX")
    chown root:root "$backup"
    chmod 0700 "$backup"
    trap arm_cleanup EXIT
    install -d -o root -g root -m 0700 "$backup/files" "$STATE_DIR"
    local path
    for path in "${SNAPSHOT_PATHS[@]}"; do snapshot_one "$backup" "$path"; done
    printf '%s\n' "$ssh_service" > "$backup/ssh-service"

    now=$(date +%s)
    deadline_epoch=$((now + minutes * 60))
    deadline=$(date -d "@$deadline_epoch" '+%Y-%m-%d %H:%M:%S %Z')
    deadline_utc=$(date -u -d "@$deadline_epoch" '+%Y-%m-%d %H:%M:%S UTC')
    systemd-analyze calendar "$deadline_utc" >/dev/null || die "systemd rejected rollback deadline: $deadline_utc"

    printf '[Unit]\nDescription=Restore Thessley SSH and PAM configuration backup\n\n[Service]\nType=oneshot\nExecStart=%s restore %s\n' \
        "$SCRIPT_PATH" "$backup" > "$backup/$SERVICE_NAME"
    printf '[Unit]\nDescription=Timed Thessley SSH/PAM configuration rollback\n\n[Timer]\nOnCalendar=%s\nPersistent=true\nAccuracySec=1s\nUnit=%s\n\n[Install]\nWantedBy=timers.target\n' \
        "$deadline_utc" "$SERVICE_NAME" > "$backup/$TIMER_NAME"
    install -o root -g root -m 0644 "$backup/$SERVICE_NAME" "$SERVICE_PATH"
    install -o root -g root -m 0644 "$backup/$TIMER_NAME" "$TIMER_PATH"
    printf '%s\n' "$backup" > "$ACTIVE_BACKUP.tmp"
    chown root:root "$ACTIVE_BACKUP.tmp"
    chmod 0600 "$ACTIVE_BACKUP.tmp"
    mv -f -- "$ACTIVE_BACKUP.tmp" "$ACTIVE_BACKUP"

    systemctl daemon-reload
    systemctl enable --now "$TIMER_NAME"
    systemctl is-active --quiet "$TIMER_NAME" || die 'systemd did not activate the rollback timer.'
    next=$(systemctl show "$TIMER_NAME" --property=NextElapseUSecRealtime --value)
    [[ -n $next && $next != n/a ]] || die 'systemd reports no scheduled rollback time.'
    next_epoch=$(date -d "$next" +%s) || die "cannot parse Task Scheduler deadline reported by systemd: $next"
    (( next_epoch >= deadline_epoch - 60 && next_epoch <= deadline_epoch + 60 )) \
        || die "systemd scheduled $next instead of the requested deadline $deadline_utc."
    armed=1
    trap - EXIT

    echo "Rollback timer is active: $deadline / $deadline_utc."
    echo "It restores SSH/PAM configuration and Thessley SSH login policies (not phone keys, VPN settings, or the whole app)."
    echo "Keep this SSH session open. After a fresh SSH login succeeds, cancel with: sudo $SCRIPT_PATH cancel"
    echo "Snapshot retained at $backup"
}

restore() {
    local backup=${1:-} path failed=0 ssh_service
    [[ -d $backup && ! -L $backup ]] \
        || die 'invalid or missing rollback snapshot path.'
    backup=$(realpath -e -- "$backup") || die 'cannot resolve rollback snapshot path.'
    [[ $(dirname -- "$backup") == /var/backups && $(basename -- "$backup") == thessley-ssh-config-rollback-* ]] \
        || die 'rollback snapshot must be a direct child of /var/backups with a Thessley rollback name.'
    [[ $(stat -c '%u' "$backup") == 0 && ! -L $backup ]] \
        || die 'rollback snapshot must be a root-owned real directory.'
    chmod 0700 "$backup"
    for path in "${SNAPSHOT_PATHS[@]}"; do
        restore_one "$backup" "$path" || failed=1
    done
    if (( failed )); then
        logger -t thessley-ssh-rollback 'restore incomplete; timer and backup retained for manual recovery'
        die "restore was incomplete. Backup retained at $backup; inspect errors, then retry with: sudo $SCRIPT_PATH restore $backup"
    fi
    if ! sshd -t; then
        logger -t thessley-ssh-rollback 'restored files failed sshd -t; SSH service was not reloaded'
        die "restored SSH config failed validation. Backup retained at $backup; the SSH daemon was not reloaded."
    fi
    ssh_service=$(cat "$backup/ssh-service")
    if ! systemctl reload "$ssh_service"; then
        logger -t thessley-ssh-rollback "restored configuration but could not reload $ssh_service"
        die "files restored, but $ssh_service could not reload. Backup retained at $backup; keep your current session open."
    fi
    cleanup_units
    rm -f -- "$ACTIVE_BACKUP"
    logger -t thessley-ssh-rollback "restored SSH and PAM config from $backup"
    echo "SSH/PAM configuration restored and $ssh_service reloaded. Backup retained at $backup"
}

cancel() {
    local backup=''
    [[ -r $ACTIVE_BACKUP ]] && backup=$(cat "$ACTIVE_BACKUP")
    if [[ ! -e $TIMER_PATH && ! -e $SERVICE_PATH ]]; then
        echo 'No Thessley SSH configuration rollback timer is pending.'
        return 0
    fi
    cleanup_units
    rm -f -- "$ACTIVE_BACKUP"
    echo 'Rollback timer cancelled; no SSH/PAM policy files were changed by this command.'
    echo 'Keep the current session open until a separate fresh SSH login has succeeded.'
    [[ -n $backup ]] && echo "Snapshot retained at $backup"
}

status() {
    if systemctl is-active --quiet "$TIMER_NAME"; then
        systemctl list-timers --all --no-legend "$TIMER_NAME"
        [[ -r $ACTIVE_BACKUP ]] && printf 'Snapshot: %s\n' "$(cat "$ACTIVE_BACKUP")"
    else
        echo 'No Thessley SSH configuration rollback timer is pending.'
    fi
}

require_root
armed=0
backup='not-created'
case ${1:-} in
    arm) shift; arm "$@" ;;
    restore) shift; restore "${1:-}" ;;
    cancel) cancel ;;
    status) status ;;
    *) die "usage: $0 arm MINUTES | status | cancel" ;;
esac
