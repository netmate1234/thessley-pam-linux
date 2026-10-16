"""thessley-pam: add, list and remove the phones that may approve logins on this computer.

    sudo thessley-pam enroll [--user NAME] [--port N]
    sudo thessley-pam list   [--user NAME]
    sudo thessley-pam remove CREDENTIAL_ID [--user NAME]
    sudo thessley-pam grace   [--service S --hours H]   ask the phone once per H hours for service S (0 = always ask)
    sudo thessley-pam require [--service S on|off]       refuse users with no phone for service S
    sudo thessley-pam passes                            who holds a phone pass right now
    sudo thessley-pam end-pass [--user NAME] [--service S]
    sudo thessley-pam keyring-link   [--user NAME]   let a phone login unlock the GNOME keyring (see keyring.py)
    sudo thessley-pam keyring-forget [--user NAME]
    sudo thessley-pam keyring-status [--user NAME]
"""

import argparse
import os
import pwd
import queue
import re
import secrets
import select
import subprocess
import sys
import threading
from urllib.parse import urlencode

from . import machine, protocol, store
from .listener import Listener

DEFAULT_PORT = 47810
ENROLL_WAIT = 180   # seconds the QR code stays valid
CONFIRM_WAIT = 90   # seconds to type "yes" once the codes are shown
LABEL = re.compile(r"^[\w .,'()+-]{1,64}$")


def _need_root() -> None:
    if os.geteuid() != 0:
        sys.exit("Run this with sudo: it changes who may log in to this computer.")


def _target_user(arg: str | None) -> str:
    name = arg or os.environ.get("SUDO_USER") or pwd.getpwuid(os.getuid()).pw_name
    try:
        pwd.getpwnam(name)
    except KeyError:
        sys.exit(f"No such user: {name}")
    return name


def _show_qr(link: str) -> None:
    subprocess.run(["qrencode", "-t", "ANSIUTF8", "-m", "2", link], check=True)


def _open_tty():
    """The controlling terminal, so the yes/no comes from a person at this computer and not from a pipe."""
    try:
        return open("/dev/tty", "r")
    except OSError:
        return None


def _ask_yes(prompt: str, timeout: int) -> bool:
    tty = _open_tty()
    if tty is None:
        return False
    with tty:
        print(prompt, end="", flush=True)
        ready, _, _ = select.select([tty], [], [], timeout)
        if not ready:
            print("\nNo answer in time.")
            return False
        return tty.readline().strip().lower() in ("y", "yes")


def cmd_enroll(args) -> int:
    _need_root()
    username = _target_user(args.user)
    tty = _open_tty()
    if tty is None:
        sys.exit("Run this in a terminal: you will be asked to type yes to confirm the phone.")
    tty.close()
    mid, host, ip = machine.machine_id(), machine.hostname(), machine.lan_ip()
    request_id = secrets.token_urlsafe(12)
    nonce = secrets.token_urlsafe(16)

    pending: queue.Queue = queue.Queue(maxsize=1)  # the one verified phone waiting for the person's yes/no
    decided = threading.Event()
    decision: dict = {}
    taken = threading.Lock()

    def respond(client_ip: str, body: dict) -> tuple[int, dict]:
        try:
            public_key = str(body["public_key"])
            signature = str(body["proof_signature"])
            timestamp = int(body["timestamp"])
            label = str(body.get("label") or "Phone").strip()
            chain = [str(c) for c in body.get("attestation_chain") or []][:10]
        except (KeyError, TypeError, ValueError):
            return 400, {"result": "error", "message": "Missing fields."}
        if not LABEL.match(label):
            label = "Phone"
        if not protocol.timestamp_ok(timestamp):
            return 400, {"result": "error", "message": "Phone clock is off by more than a minute."}
        msg = protocol.canonical("enroll", request_id, mid, username, nonce, timestamp, "register")
        if not protocol.verify(public_key, signature, msg):
            return 400, {"result": "error", "message": "Signature did not verify."}
        if not taken.acquire(blocking=False):
            return 409, {"result": "error", "message": "This code has already been used."}

        pending.put({"client_ip": client_ip, "public_key": public_key, "label": label, "chain": chain})
        if not decided.wait(CONFIRM_WAIT + 10) or not decision.get("ok"):
            return 200, {"result": "denied", "message": "Not confirmed on the computer."}
        return 200, {"result": "ok", "credential_id": decision["credential_id"], "username": username,
                     "hostname": host}

    path = f"/thessley-pam/v1/enroll/{request_id}/respond"
    with Listener(ip, args.port, {path: respond}) as lst:
        link = "thessleypam://enroll?" + urlencode({
            "h": ip, "p": args.port, "fp": lst.fingerprint, "id": request_id, "n": nonce,
            "m": mid, "hn": host, "u": username,
        })
        print(f"\nAdd a phone that may approve logins for '{username}' on {host}.\n")
        _show_qr(link)
        print(f"In Thessley Passkey: Scan QR code. Valid for {ENROLL_WAIT // 60} minutes. Ctrl+C to cancel.",
              flush=True)

        try:
            item = pending.get(timeout=ENROLL_WAIT)
        except queue.Empty:
            print("Timed out. Nothing was added.")
            return 1

        code = protocol.pairing_code(item["public_key"])
        print(f"\nPhone '{item['label']}' ({item['client_ip']}) answered.")
        print(f"\n    Code:  {code}\n")
        ok = _ask_yes("Does the phone show the same code? Type yes to add it: ", CONFIRM_WAIT)
        if ok:
            device = store.add_device(username, item["public_key"], item["label"], item["chain"])
            decision.update(ok=True, credential_id=device["credential_id"])
        decided.set()
        # Let the phone's request receive its answer before the listener shuts down.
        threading.Event().wait(1.5)

    if ok:
        print(f"Added '{item['label']}' as {decision['credential_id']} for {username}.")
        return 0
    print("Not added.")
    return 1


def cmd_list(args) -> int:
    _need_root()
    username = _target_user(args.user)
    devs = store.devices(username)
    if not devs:
        print(f"No phones enrolled for {username}.")
        return 0
    import datetime
    for d in devs:
        when = datetime.datetime.fromtimestamp(d["enrolled_at"]).strftime("%Y-%m-%d %H:%M")
        print(f"{d['credential_id']}  {d['label']:<24}  enrolled {when}" + ("  (disabled)" if d.get("disabled") else ""))
    return 0


def cmd_remove(args) -> int:
    _need_root()
    username = _target_user(args.user)
    if store.remove_device(username, args.credential_id):
        print(f"Removed {args.credential_id} for {username}.")
        return 0
    print(f"No device {args.credential_id} for {username}.")
    return 1


def cmd_keyring_link(args) -> int:
    import getpass
    from . import keyring
    _need_root()
    username = _target_user(args.user)
    if not store.devices(username):
        sys.exit(f"{username} has no enrolled phone yet: run  sudo thessley-pam enroll  first.")
    print(f"This seals {username}'s login password in this computer's TPM, so that logging in with the phone can\n"
          "unlock the GNOME keyring (saved Wi-Fi, browser and app passwords) as a typed password does.\n"
          "It is released only after the phone approves a login, and only while this computer's Secure Boot state\n"
          "is unchanged. If you change your password later, run this again.\n")
    password = getpass.getpass(f"Login password of {username}: ")
    try:
        if not keyring.check_password(username, password):
            sys.exit("That is not this account's password. Nothing was stored.")
        keyring.seal(username, password)
    except keyring.KeyringError as exc:
        sys.exit(f"Could not seal it in the TPM: {exc}")
    finally:
        password = ""
    print("Done. Log out and log in with the phone to try it.")
    return 0


def cmd_keyring_forget(args) -> int:
    from . import keyring
    _need_root()
    username = _target_user(args.user)
    print("Deleted." if keyring.forget(username) else "Nothing was stored.")
    return 0


def cmd_keyring_status(args) -> int:
    from . import keyring
    _need_root()
    username = _target_user(args.user)
    if not keyring.is_linked(username):
        print(f"{username}: no sealed password. A phone login will not unlock the keyring.")
        return 0
    try:
        keyring.unseal(username)
        print(f"{username}: sealed and readable now. A phone login will unlock the keyring.")
        return 0
    except keyring.KeyringError as exc:
        print(f"{username}: sealed, but cannot be opened now ({str(exc)[-120:]}).\n"
              "Likely the Secure Boot state changed since it was sealed: run  sudo thessley-pam keyring-link  again.")
        return 1


def cmd_grace(args) -> int:
    from . import grants
    _need_root()
    if args.service is None:
        cfg = grants._load_config().get("grace", {})
        if not cfg:
            print("Every login asks the phone (no grace time is set for any service).")
        for svc, hours in sorted(cfg.items()):
            print(f"{svc}: the phone is asked once per {hours:g} h")
        return 0
    if args.hours is None:
        sys.exit("Say how long: --hours 4 (or --hours 0 to ask every time).")
    try:
        grants.set_grace(args.service, args.hours)
    except ValueError as exc:
        sys.exit(str(exc))
    hours = grants.grace_hours(args.service)
    if hours > 0:
        print(f"{args.service}: after one approval the same user from the same address needs no phone for {hours:g} h.\n"
              "(The pass is tied to the user, the service and the client's address, not to the ssh key.)")
    else:
        ended = grants.revoke(service=args.service)
        print(f"{args.service}: every login asks the phone again." + (f" Ended {ended} pass(es)." if ended else ""))
    return 0


def cmd_require(args) -> int:
    from . import grants
    _need_root()
    if args.service is None:
        names = grants._load_config().get("require", [])
        print("Phone required for: " + ", ".join(names) if names else "No service refuses users who have no phone.")
        return 0
    if args.state not in ("on", "off"):
        sys.exit("Say on or off.")
    try:
        grants.set_require(args.service, args.state == "on")
    except ValueError as exc:
        sys.exit(str(exc))
    print(f"{args.service}: a user with no enrolled phone is " + ("refused." if args.state == "on" else "let through (no phone step)."))
    return 0


def cmd_passes(args) -> int:
    from . import grants
    _need_root()
    rows = grants.all_passes()
    if not rows:
        print("No phone pass is active.")
        return 0
    for p in rows:
        print(f"{p['user']:<12} {p['service']:<10} from {p['rhost']:<18} {grants.remaining(p):>9} left   phone {p['credential']}")
    return 0


def cmd_end_pass(args) -> int:
    from . import grants
    _need_root()
    ended = grants.revoke(args.user, args.service)
    print(f"Ended {ended} pass(es)." if ended else "No such pass.")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="thessley-pam")
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("enroll", help="add a phone for a user (default: the user who ran sudo)")
    e.add_argument("--user")
    e.add_argument("--port", type=int, default=DEFAULT_PORT)
    e.set_defaults(func=cmd_enroll)
    ls = sub.add_parser("list", help="list a user's phones")
    ls.add_argument("--user")
    ls.set_defaults(func=cmd_list)
    rm = sub.add_parser("remove", help="remove one of a user's phones")
    rm.add_argument("credential_id")
    rm.add_argument("--user")
    rm.set_defaults(func=cmd_remove)
    g = sub.add_parser("grace", help="ask the phone once per N hours for a PAM service (e.g. sshd)")
    g.add_argument("--service")
    g.add_argument("--hours", type=float)
    g.set_defaults(func=cmd_grace)
    rq = sub.add_parser("require", help="refuse logins by users with no enrolled phone for a PAM service")
    rq.add_argument("--service")
    rq.add_argument("state", nargs="?")
    rq.set_defaults(func=cmd_require)
    ps = sub.add_parser("passes", help="list the active phone passes")
    ps.set_defaults(func=cmd_passes)
    ep = sub.add_parser("end-pass", help="end phone passes now")
    ep.add_argument("--user")
    ep.add_argument("--service")
    ep.set_defaults(func=cmd_end_pass)
    for name, fn, text in (("keyring-link", cmd_keyring_link, "seal the login password so a phone login unlocks the GNOME keyring"),
                           ("keyring-forget", cmd_keyring_forget, "delete the sealed password"),
                           ("keyring-status", cmd_keyring_status, "show whether the sealed password can be opened")):
        k = sub.add_parser(name, help=text)
        k.add_argument("--user")
        k.set_defaults(func=fn)
    args = ap.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nCancelled.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
