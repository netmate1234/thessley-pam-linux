"""The PAM step: ask the user's enrolled phone to approve, called by pam_exec after the password.

/etc/pam.d/sudo, right after @include common-auth:

    auth required pam_exec.so stdout seteuid /usr/local/lib/thessley-pam/pam-helper

Exit 0 only for a valid, signed "approve" from one of the user's enrolled phones. Everything else (deny,
timeout, bad signature, phone unreachable, any error) exits non-zero, so sudo is refused: strict on purpose.
A user with no enrolled phone is not affected (exit 0), so the line can't lock out anyone who never opted in.

Whatever is printed on stdout is shown to the person by sudo (pam_exec's stdout option), line by line.
"""

import os
import secrets
import subprocess
import sys
import syslog
import threading
import time
from urllib.parse import urlencode

from . import machine, protocol, store
from .listener import Listener

PORT = 47810
WAIT = 60  # seconds to approve on the phone

OK, REFUSED = 0, 1


def _log(msg: str, warn: bool = False) -> None:
    syslog.openlog("thessley-pam", syslog.LOG_PID, syslog.LOG_AUTHPRIV)
    syslog.syslog(syslog.LOG_WARNING if warn else syslog.LOG_INFO, msg)


def _say(text: str) -> None:
    print(text, flush=True)


def run(env: dict) -> int:
    if env.get("PAM_TYPE") != "auth":
        return OK  # only the auth step is ours; account/session/password pass through
    username = env.get("PAM_USER", "")
    service = env.get("PAM_SERVICE", "")
    tty = env.get("PAM_TTY", "") or "-"
    try:
        devices = store.devices(username)
    except KeyError:
        _log(f"unknown user {username!r} ({service})", warn=True)
        return REFUSED
    if not devices:
        return OK

    by_id = {d["credential_id"]: d for d in devices}
    mid, host, ip = machine.machine_id(), machine.hostname(), machine.lan_ip()
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
            signature = str(body["signature"])
        except (KeyError, TypeError, ValueError):
            return 400, {"result": "error", "message": "Missing fields."}
        device = by_id.get(cred)
        if device is None:
            return 403, {"result": "error", "message": "This phone is not enrolled for this user here."}
        if action not in ("approve", "deny"):
            return 400, {"result": "error", "message": "Unknown action."}
        if not protocol.timestamp_ok(timestamp):
            return 400, {"result": "error", "message": "Phone clock is off by more than a minute."}
        msg = protocol.canonical("sudo", request_id, mid, username, nonce, timestamp, action)
        if not protocol.verify(device["public_key"], signature, msg):
            _log(f"bad signature from {client_ip} for {username} ({cred})", warn=True)
            return 400, {"result": "error", "message": "Signature did not verify."}
        if not taken.acquire(blocking=False):
            return 409, {"result": "error", "message": "This request has already been answered."}
        outcome.update(action=action, cred=cred, label=device.get("label", ""), ip=client_ip)
        done.set()
        return 200, {"result": "ok"}

    path = f"/thessley-pam/v1/sudo/{request_id}/respond"
    try:
        with Listener(ip, PORT, {path: respond}) as lst:
            link = "thessleypam://sudo?" + urlencode({
                "h": ip, "p": PORT, "fp": lst.fingerprint, "id": request_id, "n": nonce,
                "m": mid, "hn": host, "u": username, "tty": tty,
            })
            qr = subprocess.run(["/usr/bin/qrencode", "-t", "UTF8", "-m", "2", link],
                                check=True, capture_output=True, text=True).stdout
            _say(f"Approve {service} for {username} on {host} with Thessley Passkey (scan within {WAIT} s):")
            for line in qr.splitlines():
                _say(line)
            approved_in_time = done.wait(WAIT)
            time.sleep(0.5)  # let the phone receive its reply before the listener closes
    except OSError as e:
        _say(f"Thessley Passkey: could not start ({e.strerror}). Refusing.")
        _log(f"listener failed for {username}: {e}", warn=True)
        return REFUSED

    if not approved_in_time:
        _say("Thessley Passkey: no answer from the phone. Refusing.")
        _log(f"timeout for {username} ({service}, {tty})", warn=True)
        return REFUSED
    if outcome["action"] != "approve":
        _say("Thessley Passkey: denied on the phone.")
        _log(f"denied by {outcome['label']!r} ({outcome['cred']}) for {username} ({service}, {tty})", warn=True)
        return REFUSED

    try:
        store.touch(username, outcome["cred"])
    except OSError:
        pass  # last_used is informational; never fail a valid approval over it
    _log(f"approved by {outcome['label']!r} ({outcome['cred']}) from {outcome['ip']} for {username} "
         f"({service}, {tty})")
    return OK


def main() -> int:
    try:
        return run(dict(os.environ))
    except Exception as e:  # strict: any unexpected failure refuses
        _log(f"error: {e!r}", warn=True)
        print("Thessley Passkey: internal error. Refusing.", flush=True)
        return REFUSED


if __name__ == "__main__":
    sys.exit(main())
