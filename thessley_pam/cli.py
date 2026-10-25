"""thessley-pam: add, list and remove the devices that may approve logins on this computer.

    sudo thessley-pam enroll [--user NAME] [--port N]            (prints the link as text above the QR code; --link is accepted, no longer needed)
    sudo thessley-pam list   [--user NAME]
    sudo thessley-pam remove CREDENTIAL_ID [--user NAME]
    sudo thessley-pam grace   [--service S --hours H]   ask the device once per H hours for service S (0 = always ask)
    sudo thessley-pam require [--service S on|off]       refuse users with no device for service S
    sudo thessley-pam show-link [on|off]             print each approval's link as text (on by default)
    sudo thessley-pam enroll-me [--link]            a user adds a device for their own account (see install-selfenroll.sh)
    sudo thessley-pam self-enroll [on|off]          may users do that (on by default); the 2nd device needs the 1st to approve
    sudo thessley-pam web [status|on|off|serve|listen ADDR|port N|session MIN|cert FILE KEY]   the admin web page (web.py)
    sudo thessley-pam vpn [status|on|off|enroll [USER]|mark CRED [USER]|unmark CRED [USER]|public-host NAME|server-port N|page-port N|group G|wait SEC]   the OpenVPN second step (vpn.py)
    sudo thessley-pam approvals serve                      shared SSH/local QR listener (VPN remains on port 47830)
    sudo thessley-pam passes                            who holds a device pass right now
    sudo thessley-pam end-pass [--user NAME] [--service S]
    sudo thessley-pam keyring-link   [--user NAME]   let a device login unlock the GNOME keyring (see keyring.py)
    sudo thessley-pam keyring-forget [--user NAME]
    sudo thessley-pam keyring-status [--user NAME]
"""

import argparse
import base64
import hashlib
import os
import pwd
import hmac
import queue
import re
import secrets
import select
import subprocess
import sys
import threading
import time
from urllib.parse import urlencode

from . import grants, listener, machine, pam, protocol, store, tpmproof

DEFAULT_PORT = 47810
ENROLL_WAIT = 180   # seconds the QR code stays valid
CONFIRM_WAIT = 90   # seconds to type "yes" once the codes are shown
LABEL = re.compile(r"^[\w .,'()+-]{1,64}$")
APPROVE_SERVICE = "thessley-enroll"  # the name the phone sees on the "adding a device?" request (display only)


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


def qr_style(modules: int, cols: int, rows: int, remote: bool) -> str:
    """How `thessley-pam enroll` draws its QR code in a terminal. "big" = two characters per module (twice the size in both
    directions: a module is then about square), when the window is large enough for it; otherwise the compact half-block form.
    Never big over ssh: that is a login prompt in someone else's window, where size is limited (and the ssh logins keep the compact
    form in pam.py anyway)."""
    if remote:
        return "compact"
    return "big" if cols >= 2 * modules + 2 and rows >= modules + 6 else "compact"


def _show_qr(link: str) -> None:
    import shutil
    remote = bool(os.environ.get("SSH_CONNECTION") or os.environ.get("SSH_TTY") or os.environ.get("SSH_CLIENT"))
    size = shutil.get_terminal_size((80, 24))
    try:   # the number of modules, from the compact form (one row = two modules)
        rows_compact = subprocess.run(["qrencode", "-t", "UTF8", "-m", "2", link], check=True, capture_output=True, text=True).stdout.splitlines()
        modules = len(rows_compact) * 2
    except (OSError, subprocess.CalledProcessError):
        modules = 10 ** 6
    style = qr_style(modules, size.columns, size.lines, remote)
    subprocess.run(["qrencode", "-t", "ANSI" if style == "big" else "ANSIUTF8", "-m", "2", link], check=True)


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
        sys.exit("Run this in a terminal: you will be asked to type yes to confirm the device.")
    tty.close()
    # The helpers are looked up when called, so a test (or another front end) can replace them.
    extra = {"vh": args.vpn_host} if getattr(args, "vpn_host", None) else None
    device = _enroll_flow(username, args.port, say=lambda text: print(text, flush=True),
                          ask_yes=lambda prompt, timeout: _ask_yes(prompt, timeout), show_qr=lambda link: _show_qr(link),
                          link_extra=extra)
    return 0 if device else 1


def _enroll_flow(username: str, port: int, say, ask_yes, show_qr=None, cancel: threading.Event | None = None,
                 enroll_wait: float = ENROLL_WAIT, confirm_wait: float = CONFIRM_WAIT, link_extra: dict | None = None):
    """Add one device for `username`: show the link (and QR), wait for the device, show the pairing code, ask whether the
    codes match. Returns the stored device, or None. Used by the command line (say = print, ask_yes = a prompt on the
    terminal) and by the admin web page (say collects lines for the page, ask_yes waits for a button, cancel is set
    when the person leaves the page)."""
    mid, host, ip = machine.machine_id(), machine.hostname(), machine.lan_ip()
    request_id = secrets.token_urlsafe(12)
    nonce = secrets.token_urlsafe(16)
    cancel = cancel or threading.Event()

    pending: queue.Queue = queue.Queue(maxsize=1)  # the one verified phone waiting for the person's yes/no
    decided = threading.Event()
    decision: dict = {}
    taken = threading.Lock()
    tpm_state: dict = {}  # what the one TPM challenge of this enrolment issued (one challenge, one attempt)

    def b64(raw: bytes) -> str:
        return base64.b64encode(raw).decode()

    def tpm_challenge(client_ip: str, body: dict) -> tuple[int, dict]:
        """Step 1 of the TPM proof: the app sends its endorsement key certificates and a fresh attestation key; we check
        the certificates against the manufacturer roots and answer with a secret only that chip can recover."""
        def refused(reason: str):
            return 400, {"result": "error", "message": f"The TPM could not be verified: {reason}."}
        if tpm_state:
            return 409, {"result": "error", "message": "A TPM challenge was already issued for this enrolment."}
        try:
            certs, ak = body["ek_certs"], body["ak_public"]
            if not isinstance(certs, list) or not isinstance(ak, str) or len(ak) > 1024:
                raise ValueError
            ders = [base64.b64decode(c, validate=True) for c in certs]
            ak_public = base64.b64decode(ak, validate=True)
        except (KeyError, ValueError, TypeError):
            return 400, {"result": "error", "message": "Missing TPM details."}
        ek = tpmproof.verify_ek_chain(ders)
        if ek is None:
            return refused("the TPM certificate chain is not one we trust")
        try:
            attributes = tpmproof.parse_public(ak_public)["attributes"]
            need = tpmproof.ATTR_FIXEDTPM | tpmproof.ATTR_FIXEDPARENT | tpmproof.ATTR_RESTRICTED | tpmproof.ATTR_SIGN
            if attributes & need != need:
                return refused("attestation key is not a restricted signing key")
            secret = os.urandom(32)
            cred = tpmproof.make_credential(ek["x"], ek["y"], tpmproof.name(ak_public), secret)
        except tpmproof.TpmProofError:
            return refused("could not build the challenge")
        tpm_state.update(ak=hashlib.sha256(ak_public).digest(), secret=hashlib.sha256(secret).digest(),
                         maker=ek["manufacturer"], model=ek["model"])
        return 200, {"credential_blob": b64(cred["credential_blob"]), "secret": b64(cred["secret"])}

    def check_tpm(public_key: str, tpm: dict | None) -> dict | None:
        """Step 2: the app's proof that its signing key lives in the TPM we challenged. What this computer concluded."""
        state = dict(tpm_state)
        tpm_state.clear()  # one challenge, one attempt
        if tpm is None:
            return None
        def no(reason: str) -> dict:
            return {"level": "unverified", "reason": reason}
        if not state:
            return no("no challenge was issued")
        try:
            field = {k: base64.b64decode(str(tpm[k]), validate=True)
                     for k in ("ak_public", "activated_secret", "certify_info", "certify_signature", "key_public")}
            spki = base64.b64decode(public_key, validate=True)
        except (KeyError, ValueError, TypeError):
            return no("incomplete proof")
        if not hmac.compare_digest(state["ak"], hashlib.sha256(field["ak_public"]).digest()):
            return no("a different attestation key than the one challenged")
        if not hmac.compare_digest(state["secret"], hashlib.sha256(field["activated_secret"]).digest()):
            return no("the activation secret does not match (the key and the TPM certificate are not in the same chip)")
        reason = tpmproof.verify_certification(field["ak_public"], field["certify_info"], field["certify_signature"],
                                               field["key_public"], nonce.encode("ascii"), spki)
        if reason:
            return no(reason)
        return {"level": "tpm", "maker": state["maker"], "model": state["model"], "checked_at": int(time.time())}

    def respond(client_ip: str, body: dict) -> tuple[int, dict]:
        try:
            public_key = str(body["public_key"])
            signature = str(body["proof_signature"])
            timestamp = int(body["timestamp"])
            label = str(body.get("label") or "Device").strip()
            chain = [str(c) for c in body.get("attestation_chain") or []][:10]
        except (KeyError, TypeError, ValueError):
            return 400, {"result": "error", "message": "Missing fields."}
        if not LABEL.match(label):
            label = "Device"
        if not protocol.timestamp_ok(timestamp):
            return 400, {"result": "error", "message": "Device clock is off by more than a minute."}
        msg = protocol.canonical("enroll", request_id, mid, username, nonce, timestamp, "register")
        if not protocol.verify(public_key, signature, msg):
            return 400, {"result": "error", "message": "Signature did not verify."}
        if not taken.acquire(blocking=False):
            return 409, {"result": "error", "message": "This code has already been used."}

        tpm = body.get("tpm")
        attestation = check_tpm(public_key, tpm if isinstance(tpm, dict) else None)
        pending.put({"client_ip": client_ip, "public_key": public_key, "label": label, "chain": chain,
                     "attestation": attestation})
        if not decided.wait(confirm_wait + 10) or not decision.get("ok"):
            if decision.get("error"):
                return 500, {"result": "error", "message": "The computer could not save this device: " + decision["error"]}
            return 200, {"result": "denied", "message": "Not confirmed on the computer."}
        return 200, {"result": "ok", "credential_id": decision["credential_id"], "username": username,
                     "hostname": host, "attestation": "tpm" if (attestation or {}).get("level") == "tpm" else ""}

    path = f"/thessley-pam/v1/enroll/{request_id}/respond"
    tpm_path = f"/thessley-pam/v1/enroll/{request_id}/tpm-challenge"
    device = None
    with listener.listening(ip, {path: respond, tpm_path: tpm_challenge}, port) as lst:
        link = "thessleypam://enroll?" + urlencode({
            "h": ip, "p": lst.port, "fp": lst.fingerprint, "id": request_id, "n": nonce,
            "m": mid, "hn": host, "u": username, **(link_extra or {}),
        })
        say(f"\nAdd a device that may approve logins for '{username}' on {host}.\n")
        say(f"Link: {link}\n")  # always: for the desktop app, or a phone that cannot scan this screen
        if show_qr:
            show_qr(link)
        say(f"In Thessley Passkey: Scan QR code. Valid for {int(enroll_wait) // 60} minutes. Ctrl+C to cancel.")

        item = None
        waited = 0.0
        while item is None and waited < enroll_wait and not cancel.is_set():
            try:
                item = pending.get(timeout=1)
            except queue.Empty:
                waited += 1
        if item is None:
            decided.set()
            say("Cancelled. Nothing was added." if cancel.is_set() else "Timed out. Nothing was added.")
            return None

        code = protocol.pairing_code(item["public_key"])
        say(f"\nPhone '{item['label']}' ({item['client_ip']}) answered.")
        say(f"\n    Code:  {code}\n")
        att = item.get("attestation")
        if att:
            say("    TPM:   " + (f"verified, a genuine TPM 2.0 chip ({(att['maker'] + ' ' + att['model']).strip() or 'maker not named'})"
                                 if att["level"] == "tpm" else f"claimed but NOT verified ({att['reason']})") + "\n")
        ok = ask_yes("Does the device show the same code? Type yes to add it: ", confirm_wait)
        try:
            if ok:
                device = store.add_device(username, item["public_key"], item["label"], item["chain"], item.get("attestation"),
                                      vpn_host=(link_extra or {}).get("vh", ""))
                decision.update(ok=True, credential_id=device["credential_id"])
        except OSError as e:
            decision["error"] = str(e)
            say(f"Could not save the device: {e}")
        finally:
            decided.set()  # always answer the device, or it waits for the full timeout
        # Let the phone's request receive its answer before the listener shuts down.
        threading.Event().wait(1.5)

    if device:
        say(f"Added '{item['label']}' as {device['credential_id']} for {username}.")
        return device
    say("Not added.")
    return None


def self_enroll_route(username: str | None) -> tuple[str | None, str]:
    """How this account may enrol a device itself: ("first", "") when it has none, ("approve", "") when it has one that
    must say yes first, or (None, why not). A first device is the only one nobody has to approve; anyone who can run a
    session as the account (it takes its password) could add one, so any further device needs a fresh approval from
    a device already enrolled (no pass ever counts), and devices that are all switched off (lost) need an administrator."""
    if not username or username == "root":
        return None, "This is for a normal user, run through sudo. An administrator uses: sudo thessley-pam enroll --user NAME"
    try:
        pwd.getpwnam(username)
    except KeyError:
        return None, f"No such user: {username}"
    if not grants.self_enroll_allowed():
        return None, "Adding a device yourself is switched off on this computer. Ask an administrator."
    devices = store.devices(username)
    if any(not d.get("disabled") for d in devices):
        return "approve", ""
    if devices:
        return None, "Your devices are switched off here, so a new one needs an administrator."
    return "first", ""


def self_enroll_problem(username: str | None) -> str | None:
    route, why = self_enroll_route(username)
    return why if route is None else None


def cmd_enroll_me(args) -> int:
    """For a normal user, through sudo (install-selfenroll.sh allows exactly this command). The account is whoever
    sudo says is calling (SUDO_USER, which the caller cannot choose): nobody can add a device for another account."""
    _need_root()
    username = os.environ.get("SUDO_USER")
    route, problem = self_enroll_route(username)
    if route is None:
        print(problem)
        return 1
    import syslog
    syslog.openlog("thessley-pam", syslog.LOG_PID, syslog.LOG_AUTHPRIV)
    syslog.syslog(syslog.LOG_INFO, f"self-enrol started by {username!r} ({route})")
    if route == "approve":
        print(f"You already have a device for '{username}'. It must approve adding another one first.")
        approved = pam.run({"PAM_TYPE": "auth", "PAM_USER": username, "PAM_SERVICE": APPROVE_SERVICE, "PAM_TTY": "-"})
        if approved != pam.OK:
            print("Not approved. Nothing was added.")
            return 1
        print("Approved. Now add the new device.")
    return cmd_enroll(argparse.Namespace(user=username, port=DEFAULT_PORT, link=getattr(args, "link", False)))


def cmd_vpn(args) -> int:
    """The OpenVPN second step: settings, the daemon (serve) and OpenVPN's script (auth). See vpn.py and docs/VPN.md."""
    from . import vpn
    action, values = args.action or "status", args.values
    if action == "serve":
        return vpn.serve()
    if action == "auth":
        return vpn.authenticate(os.environ)
    _need_root()
    if action in ("mark", "unmark"):
        # For a device enrolled for the VPN before devices carried the mark: list it with the VPN devices (or take it out again).
        if not values:
            sys.exit(f"Usage: thessley-pam vpn {action} CREDENTIAL_ID [USER]")
        host = grants.vpn_settings()["public_host"] if action == "mark" else ""
        if action == "mark" and not host:
            sys.exit("Set the public host first:  sudo thessley-pam vpn public-host NAME")
        user = _target_user(values[1] if len(values) > 1 else None)
        if not store.set_vpn_host(user, values[0], host):
            sys.exit(f"No such device for {user}: {values[0]}")
        print(("Marked" if host else "Unmarked") + f" {values[0]} as a VPN device." if host else f"Unmarked {values[0]}.")
        return 0
    if action == "enroll":
        # Add a device the usual way (on this network, with the code check), and tell it which public host this computer's VPN
        # approvals will come from. The app keeps that host with the computer and accepts a VPN request on a public address
        # only from that host.
        host = grants.vpn_settings()["public_host"]
        if not host:
            sys.exit("Set the public host first:  sudo thessley-pam vpn public-host NAME")
        return cmd_enroll(argparse.Namespace(user=(values[0] if values else None), port=DEFAULT_PORT, link=False, vpn_host=host))
    if action in ("on", "off"):
        grants.set_vpn(enabled=(action == "on"))
        if os.path.exists("/etc/systemd/system/thessley-pam-vpn.service"):
            subprocess.run(["systemctl", "enable" if action == "on" else "disable", "--now", "thessley-pam-vpn"],
                           capture_output=True, check=False)
            if action == "on":
                subprocess.run(["systemctl", "restart", "thessley-pam-vpn"], capture_output=True, check=False)
        elif action == "on":
            print("The service is not installed yet: run  sudo ./install-vpn.sh  (then it starts on its own).")
    elif action in ("public-host", "server-port", "page-port", "group", "wait"):
        if len(values) != 1:
            sys.exit(f"Usage: thessley-pam vpn {action} VALUE")
        key = {"public-host": "public_host", "server-port": "server_port", "page-port": "page_port",
               "group": "socket_group", "wait": "wait"}[action]
        value = values[0]
        if key in ("server_port", "page_port", "wait"):
            if not value.isdigit():
                sys.exit(f"{action} takes a number.")
            value = int(value)
            if key in ("server_port", "page_port") and not 1 <= value <= 65535:
                sys.exit(f"{action} must be from 1 to 65535.")
        elif key == "public_host" and not re.fullmatch(r"[A-Za-z0-9.:_-]{1,253}", value):
            sys.exit("A host name or an address, nothing else.")
        grants.set_vpn(**{key: value})
    elif action != "status":
        sys.exit("Say status, on, off, enroll, mark, unmark, serve, auth, public-host, server-port, page-port, group or wait.")
    st = grants.vpn_settings()
    host = st["public_host"] or machine.lan_ip()
    print(f"VPN approval: {'ON' if st['enabled'] else 'off'}   link host {host}   UDP server port {st['server_port']}   "
          f"QR page port {st['page_port']}   "
          f"approval window {st['wait']} s   socket group {st['socket_group']}\n"
          f"  the device connects to the QR page's port {st['page_port']} as well: it is the only TCP port to forward")
    if not st["public_host"]:
        print("No public host is set: devices outside this network cannot reach the approval.  sudo thessley-pam vpn public-host NAME")
    return 0


def cmd_web(args) -> int:
    action, values = args.action or "status", args.values
    if action == "serve":
        from . import web
        return web.serve()
    _need_root()
    st = grants.web_settings()
    if action in ("on", "off"):
        grants.set_web(enabled=(action == "on"))
        if os.path.exists("/etc/systemd/system/thessley-pam-web.service"):
            subprocess.run(["systemctl", "enable" if action == "on" else "disable", "--now", "thessley-pam-web"],
                           capture_output=True, check=False)
            if action == "on":  # a restart picks up any new settings
                subprocess.run(["systemctl", "restart", "thessley-pam-web"], capture_output=True, check=False)
        elif action == "on":
            print("The service is not installed yet: run  sudo ./install-web.sh  (then it starts on its own).")
        st = grants.web_settings()
    elif action == "listen":
        grants.set_web(listen=(values[0] if values and values[0] not in ("auto", "lan") else ""))
        st = grants.web_settings()
    elif action in ("port", "session"):
        if len(values) != 1 or not values[0].isdigit():
            sys.exit(f"Usage: thessley-pam web {action} NUMBER")
        grants.set_web(**({"port": int(values[0])} if action == "port" else {"session_minutes": int(values[0])}))
        st = grants.web_settings()
    elif action == "cert":
        if len(values) != 2:
            sys.exit("Usage: thessley-pam web cert CERT_FILE KEY_FILE   (a certificate your browsers trust)")
        grants.set_web(cert=values[0], key=values[1])
        st = grants.web_settings()
    elif action != "status":
        sys.exit("Say status, on, off, serve, listen, port, session or cert.")
    from . import web
    ip = "127.0.0.1" if st["localhost_only"] else (st["listen"] or machine.lan_ip())
    cert, key = (st["cert"], st["key"]) if st["cert"] and st["key"] else web.default_cert_paths()
    print(f"Admin web page: {'ON' if st['enabled'] else 'off'}   https://{ip}:{st['port']}/   (sessions end after {st['session_minutes']} min idle)")
    if os.path.exists(cert):
        import hashlib
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        with open(cert, "rb") as f:
            der = x509.load_pem_x509_certificate(f.read()).public_bytes(serialization.Encoding.DER)
        print(f"Certificate SHA-256: {hashlib.sha256(der).hexdigest()}")
    if st["listen"] in ("0.0.0.0", "::"):
        print("It listens on every network address: make sure only networks you trust can reach this port.")
    return 0


def cmd_self_enroll(args) -> int:
    _need_root()
    if args.state is None:
        print("Users may add their own first device: " + ("yes" if grants.self_enroll_allowed() else "no"))
        return 0
    grants.set_self_enroll(args.state == "on")
    print("Users may now add their own first device." if args.state == "on"
          else "Only administrators can add devices now.")
    return 0


def cmd_list(args) -> int:
    _need_root()
    username = _target_user(args.user)
    devs = store.devices(username)
    if not devs:
        print(f"No devices enrolled for {username}.")
        return 0
    import datetime
    for d in devs:
        when = datetime.datetime.fromtimestamp(d["enrolled_at"]).strftime("%Y-%m-%d %H:%M")
        att = d.get("attestation") or {}
        proof = (f"  TPM verified ({(att.get('maker', '') + ' ' + att.get('model', '')).strip() or 'maker not named'})" if att.get("level") == "tpm"
                 else "  TPM claimed, not verified" if att.get("level") == "unverified" else "")
        print(f"{d['credential_id']}  {d['label']:<24}  enrolled {when}" + proof + ("  (disabled)" if d.get("disabled") else "")
              + (f"  [VPN {d['vpn_host']}]" if d.get("vpn_host") else ""))
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
        sys.exit(f"{username} has no enrolled device yet: run  sudo thessley-pam enroll  first.")
    print(f"This seals {username}'s login password in this computer's TPM, so that logging in with the device can\n"
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
    print("Done. Log out and log in with the device to try it.")
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
        print(f"{username}: no sealed password. A device login will not unlock the keyring.")
        return 0
    try:
        keyring.unseal(username)
        print(f"{username}: sealed and readable now. A device login will unlock the keyring.")
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
            print("Every login asks the device (no grace time is set for any service).")
        for svc, hours in sorted(cfg.items()):
            scope = "any client IP" if grants.grace_any_ip(svc) else "the same client IP"
            print(f"{svc}: the device is asked once per {hours:g} h; pass applies from {scope}")
        return 0
    if args.hours is None:
        sys.exit("Say how long: --hours 4 (or --hours 0 to ask every time).")
    try:
        grants.set_grace(args.service, args.hours, args.ip_scope)
    except ValueError as exc:
        sys.exit(str(exc))
    hours = grants.grace_hours(args.service)
    if hours > 0:
        scope = "any client IP" if grants.grace_any_ip(args.service) else "the same client IP"
        print(f"{args.service}: after one approval the same user needs no device for {hours:g} h from {scope}.\n"
              "(The pass is tied to the user and service, not to the ssh key.)")
    else:
        ended = grants.revoke(service=args.service)
        print(f"{args.service}: every login asks the device again." + (f" Ended {ended} pass(es)." if ended else ""))
    return 0


def cmd_require(args) -> int:
    from . import grants
    _need_root()
    if args.service is None:
        names = grants._load_config().get("require", [])
        print("Device required for: " + ", ".join(names) if names else "No service refuses users who have no device.")
        return 0
    if args.state not in ("on", "off"):
        sys.exit("Say on or off.")
    try:
        grants.set_require(args.service, args.state == "on")
    except ValueError as exc:
        sys.exit(str(exc))
    print(f"{args.service}: a user with no enrolled device is " + ("refused." if args.state == "on" else "let through (no device step)."))
    return 0


def cmd_show_link(args) -> int:
    _need_root()
    hide = os.path.join(store.BASE, "hide-link")
    old = os.path.join(store.BASE, "show-link")  # the earlier on-switch: no longer needed, links are shown by default
    if args.state is None:
        print("Approval requests also print their link as text." if store.show_link() else "Approval requests show only the QR code.")
        return 0
    if args.state not in ("on", "off"):
        sys.exit("Say on or off.")
    store.ensure_dirs()
    if os.path.exists(old):
        os.unlink(old)
    if args.state == "on":
        try:
            os.unlink(hide)
        except FileNotFoundError:
            pass
        print("Every sudo, ssh or device approval request also prints a line \"Link: thessleypam://...\", which the Thessley\n"
              "Passkey desktop app can approve (thessley-passkey respond LINK) and the phone app can paste. On by default.\n"
              "The login screen is not affected.")
    else:
        open(hide, "w").close()
        print("Approval requests show only the QR code now. (Enrolment always prints its link.)")
    return 0


def cmd_passes(args) -> int:
    from . import grants
    _need_root()
    rows = grants.all_passes()
    if not rows:
        print("No device pass is active.")
        return 0
    for p in rows:
        print(f"{p['user']:<12} {p['service']:<10} from {p['rhost']:<18} {grants.remaining(p):>9} left   device {p['credential']}")
    return 0


def cmd_end_pass(args) -> int:
    from . import grants
    _need_root()
    ended = grants.revoke(args.user, args.service)
    print(f"Ended {ended} pass(es)." if ended else "No such pass.")
    return 0


def cmd_approvals(args) -> int:
    from . import approvals
    return approvals.serve()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="thessley-pam")
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("enroll", help="add a device for a user (default: the user who ran sudo)")
    e.add_argument("--user")
    e.add_argument("--port", type=int, default=DEFAULT_PORT)
    e.add_argument("--link", action="store_true", help="also print the link as text (for the desktop app)")
    e.set_defaults(func=cmd_enroll)
    em = sub.add_parser("enroll-me", help="add your own first device (run through sudo by a normal user)")
    em.add_argument("--link", action="store_true", help="also print the link as text (for the desktop app)")
    em.set_defaults(func=cmd_enroll_me)
    wb = sub.add_parser("web", help="the admin web page: sign in with a phone approval, manage your keys")
    wb.add_argument("action", nargs="?", choices=("status", "on", "off", "serve", "listen", "port", "session", "cert"))
    wb.add_argument("values", nargs="*")
    wb.set_defaults(func=cmd_web)
    vp = sub.add_parser("vpn", help="the OpenVPN second step: a device must approve after the client certificate")
    vp.add_argument("action", nargs="?", choices=("status", "on", "off", "enroll", "mark", "unmark", "serve", "auth", "public-host", "server-port", "page-port", "group", "wait"))
    vp.add_argument("values", nargs="*")
    vp.set_defaults(func=cmd_vpn)
    apv = sub.add_parser("approvals", help="the shared HTTPS listener for SSH and local QR approvals")
    apv.add_argument("action", choices=("serve",))
    apv.set_defaults(func=cmd_approvals)
    se = sub.add_parser("self-enroll", help="allow or forbid users adding their own first device")
    se.add_argument("state", nargs="?", choices=("on", "off"))
    se.set_defaults(func=cmd_self_enroll)
    ls = sub.add_parser("list", help="list a user's devices")
    ls.add_argument("--user")
    ls.set_defaults(func=cmd_list)
    rm = sub.add_parser("remove", help="remove one of a user's devices")
    rm.add_argument("credential_id")
    rm.add_argument("--user")
    rm.set_defaults(func=cmd_remove)
    g = sub.add_parser("grace", help="ask the device once per N hours for a PAM service (e.g. sshd)")
    g.add_argument("--service")
    g.add_argument("--hours", type=float)
    g.add_argument("--ip-scope", choices=("same", "any"), help="limit the pass to its original client IP, or allow any IP")
    g.set_defaults(func=cmd_grace)
    rq = sub.add_parser("require", help="refuse logins by users with no enrolled device for a PAM service")
    rq.add_argument("--service")
    rq.add_argument("state", nargs="?")
    rq.set_defaults(func=cmd_require)
    sl = sub.add_parser("show-link", help="print the approval link as text under the QR code (for the desktop app)")
    sl.add_argument("state", nargs="?")
    sl.set_defaults(func=cmd_show_link)
    ps = sub.add_parser("passes", help="list the active device passes")
    ps.set_defaults(func=cmd_passes)
    ep = sub.add_parser("end-pass", help="end device passes now")
    ep.add_argument("--user")
    ep.add_argument("--service")
    ep.set_defaults(func=cmd_end_pass)
    for name, fn, text in (("keyring-link", cmd_keyring_link, "seal the login password so a device login unlocks the GNOME keyring"),
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
