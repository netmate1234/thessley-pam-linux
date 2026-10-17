"""The PAM step: ask the user's enrolled device to approve, called by pam_exec after the password.

/etc/pam.d/sudo, right after @include common-auth:

    auth required pam_exec.so stdout seteuid /usr/local/lib/thessley-pam/pam-helper

Exit 0 only for a valid, signed "approve" from one of the user's enrolled devices. Everything else (deny,
timeout, bad signature, device unreachable, any error) exits non-zero, so sudo is refused: strict on purpose.
A user with no enrolled device is not affected (exit 0), so the line can't lock out anyone who never opted in.

Whatever is printed on stdout is shown to the person by sudo (pam_exec's stdout option), line by line.
"""

import hmac
import os
import re
import secrets
import subprocess
import sys
import syslog
import threading
import time
from urllib.parse import urlencode

from . import grants, listener, machine, protocol, store

PORT = 47810
PORT_TRIES = 10  # logins at the same time each need a listener; the next free port from PORT is used (see _listening)
WAIT = 90  # seconds to approve on the phone (unlock it, find the app; the ssh module's own limit is longer, see TOTAL_WAIT_S)

OK, REFUSED = 0, 1


def _log(msg: str, warn: bool = False) -> None:
    syslog.openlog("thessley-pam", syslog.LOG_PID, syslog.LOG_AUTHPRIV)
    syslog.syslog(syslog.LOG_WARNING if warn else syslog.LOG_INFO, msg)


def _display_fields(service: str, rhost: str) -> dict:
    """Optional link fields the apps show ("ssh login from 192.168.1.111" instead of a bare "sudo"). Display only:
    the signature does not cover them, so a wrong value can mislead a person but never approve anything."""
    out = {}
    svc = re.sub(r"[^a-z0-9_-]", "", service.lower())[:32]
    if svc:
        out["s"] = svc
    if rhost and rhost != grants.LOCAL and re.fullmatch(r"[0-9A-Fa-f.:]{1,45}", rhost):
        out["r"] = rhost
    return out


def _listening(ip: str, routes: dict):
    return listener.listening(ip, routes, PORT, PORT_TRIES)


def _say(text: str) -> None:
    print(text, flush=True)


WAIT_MARKER = "THESSLEY-WAIT"  # "the code is on screen; I am now waiting for the phone" (see pam-module/pam_thessley_phone.c)
QR_MARKER = "THESSLEY-QR "  # the GNOME Shell extension draws the QR code from this line


def run(env: dict, login: bool = False, marker: bool = False, say=None, wait: float | None = None) -> int:
    """sudo mode (default): a second step after the password; users without a device pass through.

    login mode (--login, /etc/pam.d/gdm-thessley): the device *instead of* the password, on the GNOME login
    and lock screens, next to the normal password prompt. Nothing else stands between this and a session,
    so a user without a device is refused here, never let through.

    `say(line)` receives what the person should see (default: print it); the admin web page passes its own.
    """
    say = say or _say
    wait = WAIT if wait is None else wait  # read now, not at import, so tests (and the web page) can change it
    if env.get("PAM_TYPE") != "auth":
        return REFUSED if login else OK  # gdm-thessley has no other auth step; never succeed by default
    username = env.get("PAM_USER", "")
    service = env.get("PAM_SERVICE", "")
    tty = env.get("PAM_TTY", "") or "-"
    try:
        devices = store.active_devices(username)
    except KeyError:
        _log(f"unknown user {username!r} ({service})", warn=True)
        return REFUSED
    if not devices:
        if not login and grants.requires_phone(service):
            say("Thessley Passkey: no device is enrolled for this account, so this login is refused.")
            _log(f"no device for {username} ({service}); refused because a device is required here", warn=True)
            return REFUSED
        return REFUSED if login else OK
    req_type = "login" if login else "sudo"

    # A pass from an earlier approval (grace hours switched on for this service with `thessley-pam grace`): the
    # same user, service and client address need no new approval until it runs out. Never for the login screen.
    rhost = env.get("PAM_RHOST", "") or grants.LOCAL
    grace = 0.0 if login else grants.grace_hours(service)
    if grace > 0:
        try:
            held = grants.valid(username, service, rhost, {d["credential_id"] for d in devices})
        except OSError:
            held = None
        if held:
            say(f"Thessley Passkey: approved earlier, valid for another {grants.remaining(held)}.")
            _log(f"pass used for {username} ({service}, from {rhost}, {grants.remaining(held)} left)")
            return OK

    by_id = {d["credential_id"]: d for d in devices}
    mid, host, ip = machine.machine_id(), machine.hostname(), machine.lan_ip()
    # The device may have to reach this computer by another name than its LAN address (a VPN login comes from the internet,
    # through the router). The listener still binds the LAN address; only the link says where to connect. Set by the
    # trusted caller (the VPN daemon reads it from root's own settings), never taken from a user.
    link_host = env.get("PAM_PUBLIC_HOST") or ip
    request_id = secrets.token_urlsafe(12)
    nonce = secrets.token_urlsafe(16)
    done = threading.Event()
    outcome: dict = {}
    taken = threading.Lock()

    def respond(client_ip: str, body: dict) -> tuple[int, dict]:
        try:
            cred = str(body["credential_id"])
            action = str(body["action"])
            timestamp = int(body["timestamp"])
            # A "deny" may come without a signature (the phone does not ask for a fingerprint to say no); it must
            # then carry the request's nonce, which only the person who saw the link has. A refusal grants nothing.
            signature = str(body["signature"]) if "signature" in body else ""
        except (KeyError, TypeError, ValueError):
            return 400, {"result": "error", "message": "Missing fields."}
        device = by_id.get(cred)
        if device is None:
            return 403, {"result": "error", "message": "This device is not enrolled for this user here."}
        if action not in ("approve", "deny"):
            return 400, {"result": "error", "message": "Unknown action."}
        if not protocol.timestamp_ok(timestamp):
            return 400, {"result": "error", "message": "Device clock is off by more than a minute."}
        unsigned = not signature
        if unsigned:
            if action != "deny" or not hmac.compare_digest(str(body.get("nonce", "")), nonce):
                _log(f"unsigned answer refused from {client_ip} for {username} ({cred}, {action})", warn=True)
                return 400, {"result": "error", "message": "Only a refusal can be sent without a signature."}
        else:
            msg = protocol.canonical(req_type, request_id, mid, username, nonce, timestamp, action)
            if not protocol.verify(device["public_key"], signature, msg):
                _log(f"bad signature from {client_ip} for {username} ({cred})", warn=True)
                return 400, {"result": "error", "message": "Signature did not verify."}
        if not taken.acquire(blocking=False):
            return 409, {"result": "error", "message": "This request has already been answered."}
        outcome.update(action=action, cred=cred, label=device.get("label", ""), ip=client_ip, unsigned=unsigned)
        done.set()
        return 200, {"result": "ok"}

    path = f"/thessley-pam/v1/{req_type}/{request_id}/respond"
    try:
        with _listening(ip, {path: respond}) as lst:
            link = f"thessleypam://{req_type}?" + urlencode({
                "h": link_host, "p": lst.port, "fp": lst.fingerprint, "id": request_id, "n": nonce,
                "m": mid, "hn": host, "u": username, "tty": tty,
                **_display_fields(service, rhost),
            })
            if login:
                # GNOME shows no text art; the extension turns this one line into a QR code.
                say(QR_MARKER + link)
            else:
                qr = subprocess.run(["/usr/bin/qrencode", "-t", "UTF8", "-m", "2", link],
                                    check=True, capture_output=True, text=True).stdout
                say(f"Approve {service} for {username} on {host} with Thessley Passkey (scan within {wait:g} s):")
                if store.show_link() or env.get("PAM_ALWAYS_LINK"):
                    say(f"Link: {link}")  # above the QR code: it stays in view when the code scrolls the screen
                for line in qr.splitlines():
                    say(line)
            if grace > 0 and not login:
                # sshd drops text printed after its last question, so say this before the phone is answered.
                say(f"After you approve, your next login from {rhost} needs no device for {grace:g} h.")
            if marker:
                # pam_thessley_phone.so (for sshd, which holds back plain text until PAM asks a question) reads
                # everything up to this line, shows it together with a prompt, and then waits for the exit code.
                say(WAIT_MARKER)
            approved_in_time = done.wait(wait)
            time.sleep(0.5)  # let the phone receive its reply before the listener closes
    except OSError as e:
        say(f"Thessley Passkey: could not start ({e.strerror}). Refusing.")
        _log(f"listener failed for {username}: {e}", warn=True)
        return REFUSED

    if not approved_in_time:
        say("Thessley Passkey: no answer from the device. Refusing.")
        _log(f"timeout for {username} ({service}, {tty})", warn=True)
        return REFUSED
    if outcome["action"] != "approve":
        say("Thessley Passkey: denied on the device.")
        how = ", no fingerprint" if outcome.get("unsigned") else ""
        _log(f"denied by {outcome['label']!r} ({outcome['cred']}{how}) for {username} ({service}, {tty})", warn=True)
        return REFUSED

    try:
        store.touch(username, outcome["cred"])
    except OSError:
        pass  # last_used is informational; never fail a valid approval over it
    if grace > 0:
        try:
            grants.add(username, service, rhost, grace, outcome["cred"])
            say(f"Thessley Passkey: approved. Your next login from {rhost} needs no device for {grace:g} h.")
            _log(f"pass granted to {username} ({service}, from {rhost}, {grace:g} h)")
        except OSError as e:
            _log(f"could not record the pass for {username}: {e}", warn=True)  # the login itself is still approved
    _log(f"approved by {outcome['label']!r} ({outcome['cred']}) from {outcome['ip']} for {username} "
         f"({service}, {tty})")
    return OK


def main() -> int:
    try:
        return run(dict(os.environ), login="--login" in sys.argv[1:], marker="--marker" in sys.argv[1:])
    except Exception as e:  # strict: any unexpected failure refuses
        _log(f"error: {e!r}", warn=True)
        print("Thessley Passkey: internal error. Refusing.", flush=True)
        return REFUSED


if __name__ == "__main__":
    sys.exit(main())
