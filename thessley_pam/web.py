"""The admin web page: sign in with your account name and a phone approval, then manage your Thessley keys.

    sudo thessley-pam web on|off|status|serve       (serve is what the systemd service runs)
    sudo thessley-pam web listen ADDRESS            which address to listen on ("" = this computer's LAN address)
    sudo thessley-pam web port N | session MINUTES | cert FILE KEY

How it works
  * No passwords. You type your account name; the page shows the same QR code and text link as an ssh login. A phone or
    app enrolled for that account approves it with its signature (service name "thessley-web" on the phone's screen).
  * Anything that changes keys or settings asks for a fresh approval first (service "thessley-web-change"; adding a
    device is "thessley-enroll", the same wording as `thessley-pam enroll-me`). So a stolen browser session can look,
    but cannot remove, switch off or add a key.
  * You manage your own keys. Administrators (members of sudo, admin or wheel, and root) can also pick any account and
    change the settings. Every change they make is approved by their own phone.
  * It runs as root (it must read and write the key lists) and never takes a password, a command or a path from the
    browser: everything it acts on is looked up from the signed-in account and checked against a strict pattern.

The page is served over HTTPS with a certificate of its own, created on first start (a browser warns about it once
unless you give the service a real certificate with `web cert`). `web status` prints its fingerprint.
"""

from __future__ import annotations

import base64
import csv
import datetime
import grp
import hashlib
import hmac
import html
import io
import ipaddress
import json
import os
import pwd
import re
import secrets
import shlex
import socket
import ssl
import stat
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from . import cli, grants, machine, pam, store, vpn

SERVICE_LOGIN = "thessley-web"
SERVICE_CHANGE = "thessley-web-change"
SERVICE_VPN_DOWNLOAD = "thessley-vpn-download"
SERVICE_VPN_REVOKE = "thessley-vpn-revoke"
SERVICE_DEVICE = cli.APPROVE_SERVICE

USER_RE = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}$")
CRED_RE = re.compile(r"^c_[0-9a-f]{16}$")
ID_RE = re.compile(r"^[0-9a-f]{32}$")
ADMIN_GROUPS = ("sudo", "admin", "wheel")

MAX_BODY = 8 * 1024
SESSION_MAX_SECONDS = 8 * 3600
FLOW_KEEP_SECONDS = 15 * 60
LOGIN_RATE = (8, 300)  # at most 8 sign-in requests per client address in 300 s
MAX_FLOWS = 40
WEB_WAIT = 180          # seconds to approve a sign-in or a change (a person at a browser, the device in a pocket)
WEB_CONFIRM_WAIT = 180  # seconds to compare the codes and press the button when adding a device
WEB_ENROLL_WAIT = 300   # seconds the new device has to scan the code


def now() -> float:
    return time.time()


# ---- who is an administrator -------------------------------------------------------------------------------------

def is_admin(username: str) -> bool:
    try:
        entry = pwd.getpwnam(username)
    except KeyError:
        return False
    if entry.pw_uid == 0:
        return True
    for name in ADMIN_GROUPS:
        try:
            members = grp.getgrnam(name)
        except KeyError:
            continue
        if username in members.gr_mem or entry.pw_gid == members.gr_gid:
            return True
    return False


def interactive_accounts() -> list[str]:
    """Accounts an administrator can manage from the web page, including accounts with no enrolled phone yet."""
    no_login = {"/bin/false", "/usr/sbin/nologin", "/sbin/nologin", "/usr/bin/nologin"}
    names = set()
    for entry in pwd.getpwall():
        if (USER_RE.fullmatch(entry.pw_name) and (entry.pw_uid == 0 or entry.pw_uid >= 1000)
                and entry.pw_shell not in no_login):
            names.add(entry.pw_name)
    return sorted(names)


def ssh_qr_group_members() -> set[str]:
    """Return accounts for which the installed SSH PAM group policy applies."""
    try:
        group = grp.getgrnam("thessley-ssh")
    except KeyError:
        return set()
    members = set(group.gr_mem)
    for entry in pwd.getpwall():
        if entry.pw_gid == group.gr_gid:
            members.add(entry.pw_name)
    return members


# ---- one approval or enrolment in progress -----------------------------------------------------------------------

class Flow:
    """A sign-in, a step-up approval or an enrolment, driven by a thread; the page polls its state."""

    def __init__(self, kind: str, user: str, description: str = "", on_approved=None, owner: str | None = None):
        self.id = secrets.token_hex(16)
        self.owner = owner or user  # the signed-in account that started it (an administrator may act on another account)
        self.secret = secrets.token_hex(16)  # only the browser that started it knows this (a cookie)
        self.kind, self.user, self.description = kind, user, description
        self.on_approved = on_approved
        self.state = "starting"   # starting, waiting, confirm (enrolment: codes shown), approved, refused, timeout, done, failed
        self.lines: list[str] = []
        self.link = ""
        self.qr_svg_data = ""
        self.code = ""
        self.label = ""
        self.created = now()
        self.cancel = threading.Event()
        self.answer: bool | None = None
        self.answered = threading.Event()
        self.executed = False
        self.result_url = ""
        self.flash = ""
        self.lock = threading.Lock()

    def say(self, text: str) -> None:
        for line in str(text).splitlines():
            self.lines.append(line)
            m = re.match(r"Link: (thessleypam://\S+)", line)
            if m:
                self.link = m.group(1)
            m = re.search(r"Code:\s+(\d{3} \d{3})", line)
            if m:
                self.code = m.group(1)
            m = re.match(r"(?:Device|Phone) '(.*)' \(", line)
            if m:
                self.label = m.group(1)


class Session:
    def __init__(self, user: str, minutes: int):
        self.token = secrets.token_urlsafe(32)
        self.csrf = secrets.token_urlsafe(24)
        self.user = user
        self.created = self.last = now()
        self.minutes = minutes
        self.flash = ""

    def valid(self) -> bool:
        t = now()
        return t - self.last < self.minutes * 60 and t - self.created < SESSION_MAX_SECONDS


class WebApp:
    """All state and rules, apart from HTTP. Tests drive it directly or through the server."""

    def __init__(self, journal=None, qr=None, log=None):
        self.log = log or syslog_info
        self.sessions: dict[str, Session] = {}
        self.flows: dict[str, Flow] = {}
        self.vpn_downloads: dict[str, tuple[str, bytes, str, float]] = {}
        self.attempts: dict[str, list[float]] = {}
        self.lock = threading.Lock()
        self.journal = journal or journal_lines
        self.qr = qr or qr_svg
        self.httpd: Server | None = None
        self.rebind_requested = False

    def rebind(self) -> None:
        """Restart the listener after an admin changes its bind address."""
        self.rebind_requested = True
        server = self.httpd
        if server is not None:
            timer = threading.Timer(1.5, server.shutdown)
            timer.daemon = True
            timer.start()

    # -- housekeeping
    def settings(self) -> dict:
        return grants.web_settings()

    def sweep(self) -> None:
        t = now()
        with self.lock:
            for token in [k for k, s in self.sessions.items() if not s.valid()]:
                del self.sessions[token]
            for fid in [k for k, f in self.flows.items() if t - f.created > FLOW_KEEP_SECONDS]:
                self.flows[fid].cancel.set()
                self.flows[fid].answered.set()
                del self.flows[fid]
            for token in [k for k, item in self.vpn_downloads.items() if item[3] <= t]:
                del self.vpn_downloads[token]

    def issue_vpn_download(self, owner: str, body: bytes, filename: str) -> str | None:
        """Keep one approved VPN export short-lived, session-bound and single-use."""
        token = secrets.token_urlsafe(32)
        with self.lock:
            t = now()
            for expired in [k for k, item in self.vpn_downloads.items() if item[3] <= t]:
                del self.vpn_downloads[expired]
            if len(self.vpn_downloads) >= 32:
                return None
            self.vpn_downloads[token] = (owner, body, filename, t + 180)
        return token

    def take_vpn_download(self, token: str, owner: str) -> tuple[bytes, str] | None:
        with self.lock:
            item = self.vpn_downloads.get(token)
            if item is None or item[3] <= now() or item[0] != owner:
                if item is not None and item[3] <= now():
                    del self.vpn_downloads[token]
                return None
            del self.vpn_downloads[token]
            return item[1], item[2]

    def session(self, token: str | None) -> Session | None:
        if not token:
            return None
        with self.lock:
            s = self.sessions.get(token)
            if s is None:
                return None
            if not s.valid():
                del self.sessions[token]
                return None
            s.last = now()
            return s

    def rate_ok(self, ip: str) -> bool:
        limit, window = LOGIN_RATE
        t = now()
        with self.lock:
            cap = grants.web_settings()["rate_limit_entries"]
            # Expire stale buckets before admitting a new source, and keep the map bounded under distributed scans.
            if len(self.attempts) > cap or (len(self.attempts) >= cap and ip not in self.attempts):
                for old_ip, times in list(self.attempts.items()):
                    fresh = [x for x in times if t - x < window]
                    if fresh:
                        self.attempts[old_ip] = fresh
                    else:
                        self.attempts.pop(old_ip, None)
                while len(self.attempts) > cap or (len(self.attempts) >= cap and ip not in self.attempts):
                    oldest = min(self.attempts, key=lambda key: self.attempts[key][-1] if self.attempts[key] else 0)
                    self.attempts.pop(oldest, None)
            hits = [x for x in self.attempts.get(ip, []) if t - x < window]
            if len(hits) >= limit:
                self.attempts[ip] = hits
                return False
            hits.append(t)
            self.attempts[ip] = hits
            return True

    # -- starting flows
    def _new_flow(self, flow: Flow) -> Flow | None:
        self.sweep()
        with self.lock:
            if len(self.flows) >= MAX_FLOWS:
                return None
            self.flows[flow.id] = flow
        return flow

    def _approval_thread(self, flow: Flow, service: str, ip: str) -> None:
        flow.state = "waiting"
        try:
            # The browser needs the approval URI to render its QR code. Terminal
            # approvals may hide the link via the user's show-link preference,
            # but that preference must not suppress QR generation in the web UI.
            rc = pam.run({"PAM_TYPE": "auth", "PAM_USER": flow.user, "PAM_SERVICE": service,
                          "PAM_RHOST": ip, "PAM_TTY": "-", "PAM_ALWAYS_LINK": "1"},
                         say=flow.say, wait=WEB_WAIT)
        except Exception as exc:  # strict: any trouble is a refusal
            flow.say(f"error: {exc!r}")
            rc = pam.REFUSED
        text = "\n".join(flow.lines)
        flow.state = "approved" if rc == pam.OK else ("timeout" if "no answer" in text else "refused")

    def usable(self, user: str) -> bool:
        """An account that exists and has at least one device that may approve (pam.run would let anyone else straight in)."""
        if not USER_RE.match(user or ""):
            return False
        try:
            pwd.getpwnam(user)
            return bool(store.active_devices(user))
        except (KeyError, OSError):
            return False

    def start_login(self, user: str, ip: str) -> Flow | None:
        if not self.usable(user):
            return None
        flow = self._new_flow(Flow("login", user, "Sign in"))
        if flow:
            threading.Thread(target=self._approval_thread, args=(flow, SERVICE_LOGIN, ip), daemon=True).start()
        return flow

    def start_change(self, session: Session, ip: str, description: str, action, service: str = SERVICE_CHANGE) -> Flow | None:
        """A fresh approval by the signed-in account's device, then `action()` runs once (it returns (url, message))."""
        if not self.usable(session.user):
            return None
        flow = self._new_flow(Flow("change", session.user, description, on_approved=action, owner=session.user))
        if flow:
            threading.Thread(target=self._approval_thread, args=(flow, service, ip), daemon=True).start()
        return flow

    def start_enroll(self, user: str, owner: str | None = None, vpn_host: str = "") -> Flow | None:
        flow = self._new_flow(Flow("enroll", user, "Add a VPN device" if vpn_host else "Add a device", owner=owner))
        if flow is None:
            return None

        def ask_yes(prompt: str, timeout: float) -> bool:
            flow.state = "confirm"
            flow.answered.wait(timeout)
            return flow.answer is True and not flow.cancel.is_set()

        def work():
            flow.state = "waiting"
            device = None
            try:
                device = cli._enroll_flow(user, cli.DEFAULT_PORT, say=flow.say, ask_yes=ask_yes, show_qr=None, cancel=flow.cancel,
                                         enroll_wait=WEB_ENROLL_WAIT, confirm_wait=WEB_CONFIRM_WAIT,
                                         link_extra={"vh": vpn_host} if vpn_host else None)
            except Exception as exc:
                flow.say(f"error: {exc!r}")
            if not device:  # whatever went wrong, a device that was stored during this flow counts as added
                stored = [d for d in store.devices(user) if flow.label and d.get("label") == flow.label
                          and (d.get("enrolled_at") or 0) >= int(flow.created)]
                if stored:
                    device = stored[-1]
                    flow.label = flow.label or str(device.get("label", ""))
            flow.state = "done" if device else "failed"
            # Flow output contains the temporary enrollment URI and pairing code.
            self.log(f"web page: adding a device for {user} (asked by {flow.owner}): {flow.state}"
                     + (f" ({device.get('credential_id', '')})" if device else ""))

        threading.Thread(target=work, daemon=True).start()
        return flow

    def flow(self, fid: str) -> Flow | None:
        if not ID_RE.match(fid or ""):
            return None
        with self.lock:
            return self.flows.get(fid)

    def finish(self, flow: Flow) -> tuple[str, str]:
        """Once an approval came: for a sign-in the caller makes the session; for a change, run it (once)."""
        with flow.lock:
            if flow.state == "approved" and flow.kind == "change" and not flow.executed:
                flow.executed = True
                try:
                    flow.result_url, flow.flash = flow.on_approved()
                except Exception as exc:
                    flow.result_url, flow.flash = "/keys", f"That did not work: {exc}"
            return flow.result_url, flow.flash

    def new_session(self, user: str) -> Session:
        s = Session(user, self.settings()["session_minutes"])
        with self.lock:
            self.sessions[s.token] = s
        return s

    def drop_session(self, token: str) -> None:
        with self.lock:
            self.sessions.pop(token, None)

    # -- what a signed-in account may touch
    def target(self, session: Session, wanted: str | None) -> str | None:
        """The account whose keys are shown: your own, or any interactive account chosen by an administrator."""
        if not wanted or wanted == session.user:
            return session.user
        if is_admin(session.user) and USER_RE.fullmatch(wanted) and wanted in interactive_accounts():
            return wanted
        return None

    # -- the changes (each runs only after an approval)
    def change_rename(self, user: str, cred: str, label: str):
        def run():
            if not store.rename_device(user, cred, label):
                raise ValueError("no such key")
            return f"/keys?user={user}", f"Renamed to {label}."
        return run

    def change_disable(self, user: str, cred: str, off: bool):
        def run():
            if not store.set_disabled(user, cred, off):
                raise ValueError("no such key")
            return f"/keys?user={user}", "Switched off." if off else "Switched on."
        return run

    def change_remove(self, user: str, cred: str):
        def run():
            if not store.remove_device(user, cred):
                raise ValueError("no such key")
            return f"/keys?user={user}", "Removed. Its passes ended with it."
        return run

    def change_begin_enroll(self, user: str, owner: str, vpn_host: str = ""):
        def run():
            flow = self.start_enroll(user, owner, vpn_host)
            if flow is None:
                raise ValueError("too many requests at once, try again in a minute")
            return f"/enroll/{flow.id}", ""
        return run

    def change_setting(self, name: str, value: str, addresses: str = ""):
        def run():
            if name == "grace":
                grants.set_grace("sshd", float(value))
                return "/admin", f"A phone approval now lasts {float(value):g} h for ssh (0 = every login asks)."
            if name == "ssh_source_policy":
                modes = value.split(",")
                grants.set_ssh_source_policy(modes, addresses)
                labels = {
                    "any": "All IPs",
                    "local": "Local networks",
                    "vpn": "VPN networks",
                    "custom": "Chosen list",
                }
                return "/admin", "Thessley SSH source policy saved: " + ", ".join(labels[mode] for mode in modes) + "."
            if name == "session":
                grants.set_web(session_minutes=int(float(value)))
                return "/admin", f"You are now signed out after {int(float(value))} minutes without activity (from the next sign-in)."
            if name == "ssh_policy_failure":
                grants.set_ssh_policy_failure_mode(value)
                return "/admin", ("An unreadable SSH policy now fails closed; key + QR remains required."
                                   if value == "closed" else "An unreadable SSH policy allows key + password recovery.")
            if name == "web_limits":
                connections, buckets = map(int, value.split(",", 1))
                grants.set_web(max_connections=connections, rate_limit_entries=buckets)
                return "/admin", "Web connection and rate-limit memory limits saved."
            if name == "localhost_only":
                local_only = value == "on"
                grants.set_web(localhost_only=local_only)
                self.rebind()
                st = grants.web_settings()
                host = "127.0.0.1" if local_only else (st["listen"] or machine.lan_ip())
                if host in ("0.0.0.0", "::"):
                    host = machine.lan_ip()
                return f"https://{host}:{st['port']}/admin", (
                    "Admin page is now restricted to this computer at https://127.0.0.1:" + str(st["port"])
                    if local_only else f"Admin page is available at https://{host}:{st['port']}."
                )
            if name == "require":
                grants.set_require("sshd", value == "on")
                return "/admin", "Device required for ssh: " + ("on." if value == "on" else "off.")
            if name == "ssh_login_mode":
                grants.set_ssh_login_mode(value)
                labels = {
                    "phone": "SSH now requires a key and phone approval.",
                    "fallback": "SSH now prefers phone approval and falls back to the account password.",
                    "password": "SSH now requires a key and account password; phone approval is off.",
                    "qr": "SSH now requires a fresh QR phone approval; no SSH key or account password is used.",
                }
                return "/admin", labels[value]
            if name == "self_enroll":
                grants.set_self_enroll(value == "on")
                return "/admin", "Users adding their own device: " + ("on." if value == "on" else "off.")
            if name == "show_link":
                flag = os.path.join(store.BASE, "hide-link")
                if value == "on":
                    if os.path.exists(flag):
                        os.unlink(flag)
                else:
                    open(flag, "w").close()
                return "/admin", "Text links in approvals: " + ("on." if value == "on" else "off.")
            raise ValueError("unknown setting")
        return run

    def change_ssh_policy(self, qr_only: bool, key_qr: bool, key_password: bool):
        def run():
            grants.set_ssh_login_paths(qr_only, key_qr, key_password)
            paths = []
            if qr_only:
                paths.append("QR-only with the configured SSH approval pass")
            if key_qr:
                paths.append("SSH key + QR approval")
            if key_password:
                paths.append("SSH key + account password")
            message = "SSH login paths saved: " + "; ".join(paths) + "."
            return "/admin", message
        return run

    def change_ssh_user_policy(self, username: str, inherit: bool, qr_only: bool, key_qr: bool,
                               key_password: bool, blocked: bool):
        def run():
            grants.set_ssh_user_login_paths(username, inherit, qr_only, key_qr, key_password, blocked)
            return "/admin", f"SSH access settings saved for {username}."
        return run

    def change_ssh_user_blocked(self, username: str, blocked: bool):
        def run():
            grants.set_ssh_user_blocked(username, blocked)
            action = "blocked" if blocked else "unblocked"
            return "/admin", f"SSH access {action} for {username}. Existing SSH sessions remain open."
        return run

    # -- per-key details
    def key_usage(self) -> dict[str, tuple[int, str, str]]:
        """credential id -> (times it approved, when last, from which address) from the journal."""
        out: dict[str, list] = {}
        pattern = re.compile(r"approved by '.*?' \((?P<cred>c_\w+)\) from (?P<ip>[\d.:]+) for \S+ \((?P<svc>[\w-]+)")
        for line in self.journal():
            m = re.match(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)\S* \S+ thessley-pam\[\d+\]: (.*)$", line)
            hit = pattern.search(m.group(2)) if m else None
            if hit:
                entry = out.setdefault(hit["cred"], [0, "", ""])
                entry[0] += 1
                entry[1], entry[2] = m.group(1).replace("T", " "), hit["ip"]
        return {k: (v[0], v[1], v[2]) for k, v in out.items()}

    def key_details(self, user: str, device: dict, usage: dict) -> list[tuple[str, str]]:
        """Everything worth knowing about one key, as (name, value) rows."""
        cred = device["credential_id"]
        rows = attestation_facts(device.get("attestation_chain") or [], device.get("attestation")) + public_key_facts(device.get("public_key", ""))
        count, when, ip = usage.get(cred, (0, "", ""))
        rows.append(("Approvals in the log", f"{count}" + (f", the last on {when} from {ip}" if count else "")))
        try:
            held = [p for p in grants.all_passes() if p.get("user") == user and p.get("credential") == cred]
        except OSError:
            held = []
        rows.append(("Passes it granted that are still valid",
                     "; ".join(f"{p['service']} from {p['rhost']} ({grants.remaining(p)} left)" for p in held) or "none"))
        return rows

    # -- the activity log
    def activity(self, user: str | None) -> list[tuple[str, str]]:
        out = []
        for line in self.journal():
            parsed = parse_activity(line, user)
            if parsed:
                out.append(parsed)
        return out[-3000:][::-1]


# ---- what is known about a key -----------------------------------------------------------------------------------

ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17"  # Android key attestation: the extension that says where the key lives
SECURITY_LEVELS = {0: "Software only", 1: "Trusted environment (TEE)", 2: "StrongBox (separate secure chip)"}


def _der(data: bytes, pos: int) -> tuple[int, int, int]:
    """One DER element at pos: (tag, start of its content, end of its content)."""
    tag = data[pos]
    first = data[pos + 1]
    if first < 0x80:
        length, start = first, pos + 2
    else:
        n = first & 0x7F
        length, start = int.from_bytes(data[pos + 2:pos + 2 + n], "big"), pos + 2 + n
    if start + length > len(data):
        raise ValueError("truncated")
    return tag, start, start + length


def parse_key_description(raw: bytes) -> dict:
    """The first fields of an Android KeyDescription: attestation version and where the key was made and is kept."""
    tag, start, end = _der(raw, 0)
    if tag != 0x30:
        raise ValueError("not a sequence")
    values, pos = [], start
    for _ in range(4):  # attestationVersion, attestationSecurityLevel, keymasterVersion, keymasterSecurityLevel
        t, s, e = _der(raw, pos)
        values.append(int.from_bytes(raw[s:e], "big"))
        pos = e
    return {"version": values[0], "attestation_level": values[1], "key_level": values[3]}


def public_key_facts(public_key_b64: str) -> list[tuple[str, str]]:
    """Algorithm and fingerprint of a stored public key (base64 SubjectPublicKeyInfo)."""
    try:
        der = base64.b64decode(public_key_b64)
        key = serialization.load_der_public_key(der)
    except Exception:
        return [("Public key", "could not be read")]
    algo = "unknown"
    if isinstance(key, ec.EllipticCurvePublicKey):
        algo = f"ECDSA on {key.curve.name} (signs with SHA-256)"
    digest = hashlib.sha256(der).hexdigest()
    return [("Algorithm", algo), ("Key fingerprint (SHA-256)", ":".join(digest[i:i + 4] for i in range(0, 32, 4)) + "…")]


def tpm_proof_facts(record: dict | None) -> list[tuple[str, str]]:
    """What this computer itself concluded about a TPM key at enrolment (see tpmproof.py)."""
    if not record:
        return []
    if record.get("level") == "tpm":
        maker = (str(record.get("maker", "")) + " " + str(record.get("model", ""))).strip() or "a maker that is not named"
        when = ""
        if record.get("checked_at"):
            when = " on " + datetime.datetime.fromtimestamp(int(record["checked_at"])).strftime("%Y-%m-%d %H:%M")
        return [("TPM 2.0 proof", f"Verified by this computer{when}: a genuine TPM 2.0 chip from {maker} holds this key. It was "
                                  "created inside the chip and cannot leave it. Checked against the manufacturer roots shipped "
                                  "with this program; revocation lists are not checked."),
                ("TPM maker", maker)]
    return [("TPM 2.0 proof", f"The app claimed a TPM-held key but this computer could not verify it: {record.get('reason', 'no reason given')}.")]


def attestation_facts(chain: list[str], record: dict | None = None) -> list[tuple[str, str]]:
    """What a stored attestation chain (a device) or this computer's own TPM check (an app) says about a key. A device's chain
    is kept but not checked against a root of trust."""
    if not chain:
        if record and record.get("level") == "tpm":
            return [("Kind", "An app key (Thessley Passkey desktop app) held in a TPM chip, proven at enrolment.")] + tpm_proof_facts(record)
        return [("Kind", "An app key (Thessley Passkey desktop app): no hardware attestation was sent. Its protection (PIN, TPM chip, "
                         "security key) is set on that computer."),
                ("Hardware attestation", "none")] + tpm_proof_facts(record)
    facts = [("Kind", "A phone key (Android Keystore)")]
    try:
        certs = [x509.load_der_x509_certificate(base64.b64decode(c)) for c in chain]
    except Exception:
        return facts + [("Hardware attestation", f"{len(chain)} certificates stored, but they could not be read")]
    facts.append(("Hardware attestation", f"{len(certs)} certificates stored; this computer does not check them against a root of trust"))
    try:
        ext = certs[0].extensions.get_extension_for_oid(x509.ObjectIdentifier(ATTESTATION_OID))
        info = parse_key_description(ext.value.value)
        facts.append(("Where the key lives", SECURITY_LEVELS.get(info["key_level"], f"level {info['key_level']}")))
        facts.append(("Attestation made by", SECURITY_LEVELS.get(info["attestation_level"], f"level {info['attestation_level']}")
                      + f" (attestation version {info['version']})"))
    except (x509.ExtensionNotFound, ValueError, IndexError):
        facts.append(("Where the key lives", "the certificate carries no attestation record"))
    facts.append(("Certificate issued", certs[0].not_valid_before_utc.strftime("%Y-%m-%d")))
    return facts


# ---- certificate, QR, journal --------------------------------------------------------------------------------------

def syslog_info(message: str) -> None:
    """One line in the computer's own log (journalctl -t thessley-pam), next to the approvals."""
    try:
        import syslog
        syslog.openlog("thessley-pam", syslog.LOG_PID, syslog.LOG_AUTHPRIV)
        syslog.syslog(syslog.LOG_INFO, message)
    except Exception:  # noqa: BLE001 - logging must never break a page
        pass


def default_cert_paths() -> tuple[str, str]:
    d = os.path.join(store.BASE, "web")
    return os.path.join(d, "cert.pem"), os.path.join(d, "key.pem")


def ensure_cert(cert_path: str, key_path: str, ips: list[str]) -> str:
    """A certificate for this page, made once and kept (so a browser asks only once). Returns its SHA-256."""
    if not (os.path.exists(cert_path) and os.path.exists(key_path)):
        os.makedirs(os.path.dirname(cert_path), mode=0o700, exist_ok=True)
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, socket.gethostname())])
        when = datetime.datetime.now(datetime.timezone.utc)
        sans = [x509.DNSName(socket.gethostname())]
        for ip in ips:
            try:
                sans.append(x509.IPAddress(ipaddress.ip_address(ip)))
            except ValueError:
                pass
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(when - datetime.timedelta(minutes=5))
                .not_valid_after(when + datetime.timedelta(days=3650))
                .add_extension(x509.SubjectAlternativeName(sans), critical=False).sign(key, hashes.SHA256()))
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(cert_path, "rb") as f:
        leaf = x509.load_pem_x509_certificate(f.read())
    return hashlib.sha256(leaf.public_bytes(serialization.Encoding.DER)).hexdigest()


def qr_svg(link: str) -> bytes:
    """The QR code for a link as an SVG image, with crisp module edges in browsers."""
    svg = subprocess.run(["/usr/bin/qrencode", "-t", "SVG", "-m", "2", "-s", "6", "-o", "-", link],
                         check=True, capture_output=True, timeout=10).stdout
    # qrencode emits one adjacent SVG rectangle per dark module. At fractional CSS
    # scaling, browser antialiasing can leave thin white seams unless edges are crisp.
    return re.sub(rb"<svg(?=[\s>])", b'<svg shape-rendering="crispEdges"', svg, count=1)


def journal_lines() -> list[str]:
    try:
        out = subprocess.run(["journalctl", "-t", "thessley-pam", "-o", "short-iso", "--no-pager", "-n", "3000"],
                             capture_output=True, text=True, timeout=15).stdout
    except (OSError, subprocess.TimeoutExpired):
        return []
    return out.splitlines()


ACTIVITY = (
    (re.compile(r"approved by '(?P<who>.*?)' \((?P<cred>c_\w+)\) from (?P<ip>[\d.:]+) for (?P<user>\S+) \((?P<service>[\w-]+)"),
     lambda m: f"Approved by {m['who']} for {m['user']} ({friendly_service(m['service'])})"),
    (re.compile(r"denied by '(?P<who>.*?)' \((?P<cred>c_\w+)[^)]*\) for (?P<user>\S+) \((?P<service>[\w-]+)"),
     lambda m: f"Denied by {m['who']} for {m['user']} ({friendly_service(m['service'])})"),
    (re.compile(r"timeout for (?P<user>\S+) \((?P<service>[\w-]+)"),
     lambda m: f"No answer in time for {m['user']} ({friendly_service(m['service'])}): refused"),
    (re.compile(r"pass granted to (?P<user>\S+) \((?P<service>[\w-]+), from (?P<ip>[\d.:-]+), (?P<h>[\d.]+) h"),
     lambda m: f"Pass granted to {m['user']} from {m['ip']} for {m['h']} h"),
    (re.compile(r"no (?:device|phone) for (?P<user>\S+) \((?P<service>[\w-]+)"),
     lambda m: f"Refused {m['user']}: no device enrolled"),
    (re.compile(r"self-enrol started by '(?P<user>[^']+)'"),
     lambda m: f"{m['user']} started adding a device"),
    (re.compile(r"bad signature from (?P<ip>[\d.:]+) for (?P<user>\S+)"),
     lambda m: f"Bad signature for {m['user']} from {m['ip']}: refused"),
)


def friendly_service(name: str) -> str:
    return {"sshd": "ssh", "sudo": "sudo", "gdm-thessley": "screen login", SERVICE_LOGIN: "web sign-in",
            SERVICE_CHANGE: "a change to keys", SERVICE_DEVICE: "adding a device",
            SERVICE_VPN_DOWNLOAD: "a VPN profile download", SERVICE_VPN_REVOKE: "revoking a VPN certificate"}.get(name, name)


def parse_activity(line: str, only_user: str | None) -> tuple[str, str] | None:
    """(time, sentence) for a journal line of ours, or None; only_user limits it to one account (None = everyone)."""
    m = re.match(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)\S* \S+ thessley-pam\[\d+\]: (.*)$", line)
    if not m:
        return None
    when, text = m.group(1).replace("T", " "), m.group(2)
    for pattern, render in ACTIVITY:
        hit = pattern.search(text)
        if hit:
            who = hit.groupdict().get("user")
            if only_user is not None and who != only_user:
                return None
            return when, render(hit)
    return None


# ---- HTML ------------------------------------------------------------------------------------------------------

CSS = """
:root{--bg:#1a1b1e;--fg:#ececf0;--dim:#9a9aa3;--card:#25272c;--line:#3a3d44;--accent:#6ea1ff;--danger:#ff7b7f;--ok:#4ac26b;color-scheme:dark}
:root[data-theme="light"]{--bg:#fff;--fg:#1c1c1e;--dim:#6b6b70;--card:#f2f2f5;--line:#d8d8de;--accent:#2563eb;--danger:#c0262d;--ok:#1a7f37;color-scheme:light}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.45 system-ui,sans-serif}
main{max-width:760px;margin:0 auto;padding:20px 16px 48px}
header{display:flex;align-items:center;gap:12px;justify-content:space-between;flex-wrap:wrap;margin-bottom:8px}
h1{font-size:1.5rem;margin:.2rem 0}h2{font-size:1.1rem;margin:1.6rem 0 .5rem}
nav a,.link{color:var(--accent);text-decoration:none;margin-right:14px}nav{margin:6px 0 14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px;margin:10px 0}
.admin-users{margin:30px 0 38px;padding-bottom:18px;border-bottom:2px solid var(--line)}
.admin-users h2{margin:0 0 .45rem}.admin-users>p{margin:0 0 14px}
.dim{color:var(--dim);font-size:.9rem}.ok{color:var(--ok)}.bad{color:var(--danger)}
input[type=text]{width:100%;padding:10px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--fg);font-size:1rem}
button{padding:9px 14px;border-radius:8px;border:1px solid var(--line);background:var(--bg);color:var(--fg);font-size:.95rem;cursor:pointer}
.btn{display:inline-block;padding:11px 18px;border-radius:8px;background:var(--accent);color:#fff;text-decoration:none;font-weight:600}
.btn.small{padding:7px 12px;font-size:.9rem}
button.primary{background:var(--accent);border-color:var(--accent);color:#fff}button.danger{color:var(--danger);border-color:var(--danger)}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:8px}.row form{display:inline}
.ssh-policy-options{display:grid;gap:8px;margin:12px 0}.ssh-policy-options label{display:flex;gap:9px;align-items:flex-start}
.ssh-policy-options input[type=checkbox]{width:1.1rem;height:1.1rem;flex:0 0 auto;margin:.2rem 0 0}
.ssh-source-form{display:grid;gap:8px;margin-top:10px;min-width:0}
.ssh-source-form input[type=text]{width:100%;min-width:0;max-width:100%}
.ssh-source-options{display:grid;gap:8px;margin:10px 0}
.ssh-source-options label{display:flex;gap:9px;align-items:flex-start;min-width:0}
.ssh-source-options input[type=checkbox]{width:1.1rem;height:1.1rem;flex:0 0 auto;margin:.2rem 0 0}
.flash{border-left:4px solid var(--ok);padding:8px 12px;margin:10px 0;background:var(--card)}
code,.mono{font-family:ui-monospace,monospace;word-break:break-all;font-size:.85rem}
.qr{display:block;margin:12px auto;background:#fff;padding:6px;border-radius:8px;width:min(100%,520px);max-width:100%;height:auto;image-rendering:pixelated}
table{width:100%;border-collapse:collapse}td{padding:6px 4px;border-bottom:1px solid var(--line);vertical-align:top;font-size:.92rem}
.table-wrap{width:100%;max-width:100%;overflow-x:auto;overscroll-behavior-x:contain;-webkit-overflow-scrolling:touch}
.key-details{margin-top:8px;border-top:1px solid var(--line);min-width:0}
.key-details summary{display:flex;align-items:center;justify-content:space-between;min-height:44px;cursor:pointer;list-style:none}
.key-details summary::-webkit-details-marker{display:none}
.key-details summary::after{content:"+";font-size:1.2rem;line-height:1}
.key-details[open] summary::after{content:"−"}
.key-detail-list{margin:0;min-width:0}
.key-detail-row{display:grid;grid-template-columns:minmax(8rem,30%) minmax(0,1fr);gap:8px;padding:8px 0;border-top:1px solid var(--line);min-width:0}
.key-detail-row dt{color:var(--dim);font-size:.85rem;overflow-wrap:anywhere}
.key-detail-row dd{margin:0;min-width:0;overflow-wrap:anywhere;word-break:break-word}
.pagination{display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap;margin:12px 0}
.pagination .page-status{color:var(--dim);font-size:.9rem;text-align:center;flex:1 1 auto}
.pagination>a{margin-right:0}
.pagination a[aria-disabled='true']{opacity:.45;pointer-events:none}
.activity-time-cell{white-space:nowrap;padding-right:10px}
.activity-time{display:flex;gap:8px;align-items:baseline;white-space:nowrap;font-variant-numeric:tabular-nums}
.big{font-size:2rem;letter-spacing:.2rem;text-align:center;margin:10px 0}
@media(max-width:600px){
 .pagination{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:8px;margin:10px 0}
 .pagination .page-status{grid-column:1 / -1;grid-row:1;white-space:normal}
 .pagination>a{min-height:44px;justify-content:center;padding:8px 10px}
 .key-detail-row{grid-template-columns:minmax(0,1fr);gap:2px;padding:10px 0}
 .key-detail-row dt{font-size:.78rem;line-height:1.25}
 .key-detail-row dd{font-size:.92rem;line-height:1.35}
 .activity-time-cell{width:5rem;min-width:5rem;white-space:normal;padding-right:6px}
 .activity-time{display:block;white-space:normal;line-height:1.3}
 .activity-time-date,.activity-time-clock{display:block;font-size:.72rem;white-space:nowrap}
}
"""


def esc(value) -> str:
    return html.escape(str(value), quote=True)


def page(title: str, body: str, nonce: str, session: Session | None = None, admin: bool = False) -> str:
    nav = ""
    if session:
        nav = ('<nav><a href="/keys">Your keys</a><a href="/log">Activity</a>'
               + ('<a href="/admin">Admin</a>' if admin else "")
               + f'<form method="post" action="/logout" style="display:inline"><input type="hidden" name="csrf" value="{esc(session.csrf)}">'
                 '<button>Sign out</button></form></nav>')
    who = f'<span class="dim">Signed in as {esc(session.user)}</span>' if session else ""
    # On every page: opens the Thessley Passkey app on the computer or phone this browser runs on (no request needed).
    opener = '<a class="btn small" href="thessleypam://open">Open the Thessley app</a>'
    host = machine.hostname()  # which computer these keys are for (the address in the browser may be a tunnel's)
    return (f'<!doctype html><html lang="en" data-theme="dark"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>{esc(title)} · Thessley Passkeys for {esc(host)}</title><style>{CSS}</style>'
            f'<script nonce="{esc(nonce)}">try{{if(localStorage.getItem("thessley-theme")==="light")document.documentElement.dataset.theme="light"}}catch(e){{}}</script>'
            f'</head><body><main>'
            f'<header><h1>Thessley Passkeys for {esc(host)}</h1><span style="display:flex;gap:12px;align-items:center;flex-wrap:wrap">{who}{opener}'
            '<button id="theme-toggle" type="button" aria-pressed="true">Light mode</button></span></header>'
            f'{nav}{body}</main><script nonce="{esc(nonce)}">(()=>{{const b=document.getElementById("theme-toggle");const apply=theme=>{{document.documentElement.dataset.theme=theme;const dark=theme==="dark";b.textContent=dark?"Light mode":"Dark mode";b.setAttribute("aria-pressed",String(dark));try{{localStorage.setItem("thessley-theme",theme)}}catch(e){{}}}};apply(document.documentElement.dataset.theme||"dark");b.addEventListener("click",()=>apply(document.documentElement.dataset.theme==="dark"?"light":"dark"))}})()</script></body></html>')


def flash_html(text: str) -> str:
    return f'<div class="flash">{esc(text)}</div>' if text else ""


def login_page(message: str = "") -> str:
    return (flash_html(message) + '<div class="card"><h2 style="margin-top:0">Sign in</h2>'
            '<p class="dim">Type your account name on this computer. You will approve the sign-in on your device or in the '
            'Thessley Passkey app, with a QR code or a link. No password.</p>'
            '<form method="post" action="/login"><label for="user" class="dim">Account name</label>'
            '<input type="text" id="user" name="user" autocomplete="username" autocapitalize="none" spellcheck="false" autofocus>'
            '<div class="row"><button class="primary">Continue</button></div></form></div>')


def wait_page(flow: Flow, nonce: str, session: Session | None, heading: str, note: str) -> str:
    script = """
const id = %s;
const live = document.getElementById('live');
let last = '';
let qrReady = false;
let qrData = '';
function el(tag, text, cls) { const e = document.createElement(tag); if (text) e.textContent = text; if (cls) e.className = cls; return e; }
async function tick() {
  let again = true;
  try {
    const r = await fetch('/status/' + id + (qrReady ? '' : '?qr=1'), {credentials: 'same-origin'});
    const s = await r.json();
    if (s.next) { location.href = s.next; return; }
    if (s.qr_svg) { qrData = s.qr_svg; qrReady = true; }
    const key = JSON.stringify({...s, qr_svg: ''}) + (qrData ? ':qr-ready' : '');
    if (key !== last) {
      last = key;
      live.replaceChildren();
      if (s.link) {
        if (s.link.startsWith('thessleypam://')) {
          const open = el('a', 'Open this request in the Thessley app', 'btn'); open.href = s.link;
          live.append(open, el('p', 'On a computer or device that has the app, this opens it with this request ready.', 'dim'));
        }
        if (qrData) {
          const img = el('img', '', 'qr'); img.alt = 'QR code'; img.src = 'data:image/svg+xml;base64,' + qrData;
          img.onerror = () => { img.remove(); live.append(el('p', 'The QR code could not be displayed. Use the approval link below.', 'bad')); };
          live.append(img);
        }
        live.append(el('p', 'Or open this link in the Thessley Passkey app (paste it, or run thessley-passkey respond):', 'dim'), el('p', s.link, 'mono'));
      } else if (!s.message) {
        live.append(el('p', 'Getting the request ready…', 'dim'));
      }
      if (s.state === 'confirm') {
        live.append(el('p', 'Compare this code with the one on the new device:'), el('div', s.code, 'big'));
        const f = document.createElement('form'); f.method = 'post'; f.action = '/enroll/' + id + '/confirm';
        const h = document.createElement('input'); h.type = 'hidden'; h.name = 'csrf'; h.value = s.csrf; f.append(h);
        const row = el('div', '', 'row');
        for (const [v, t, c] of [['yes', 'The codes match', 'primary'], ['no', 'They differ', 'danger']]) {
          const b = el('button', t, c); b.name = 'answer'; b.value = v; row.append(b);
        }
        f.append(row); live.append(f);
      }
      if (s.message) live.append(el('p', s.message, s.bad ? 'bad' : 'ok'), (() => { const a = el('a', 'Back', 'link'); a.href = '/'; return a; })());
    }
    if (s.state === 'refused' || s.state === 'timeout' || s.state === 'failed' || s.state === 'gone') again = false;
  } catch (e) {}
  if (again) setTimeout(tick, 1500);
}
tick();
""" % json.dumps(flow.id)
    return (f'<div class="card"><h2 style="margin-top:0">{esc(heading)}</h2><p class="dim">{esc(note)}</p>'
            f'<div id="live"><p class="dim">Getting the request ready…</p></div></div>'
            f'<script nonce="{esc(nonce)}">{script}</script>')


def key_cards(user: str, viewer: Session, devices: list[dict], details, empty: str) -> str:
    rows = []
    for d in devices:
        cred = d["credential_id"]
        when = datetime.datetime.fromtimestamp(d.get("enrolled_at") or 0).strftime("%Y-%m-%d %H:%M") if d.get("enrolled_at") else "?"
        used = datetime.datetime.fromtimestamp(d["last_used"]).strftime("%Y-%m-%d %H:%M") if d.get("last_used") else "never"
        off = bool(d.get("disabled"))
        hidden = f'<input type="hidden" name="csrf" value="{esc(viewer.csrf)}"><input type="hidden" name="user" value="{esc(user)}"><input type="hidden" name="cred" value="{esc(cred)}">'
        vpn = f'<div class="dim">VPN approvals from {esc(d["vpn_host"])}</div>' if d.get("vpn_host") else ""
        rows.append(
            f'<div class="card"><strong>{esc(d.get("label", ""))}</strong> '
            f'{"<span class=bad>(switched off)</span>" if off else "<span class=ok>(active)</span>"}'
            f'<div class="dim">Added {esc(when)} · last used {esc(used)}</div>{vpn}<div class="mono dim">{esc(cred)}</div>'
            + key_details_html(details(d) if details else []) +
            f'<div class="row">'
            f'<form method="post" action="/keys/rename">{hidden}<input type="text" name="label" value="{esc(d.get("label", ""))}" maxlength="64" style="width:12rem"><button>Rename</button></form>'
            f'<form method="post" action="/keys/{"enable" if off else "disable"}">{hidden}<button>{"Switch on" if off else "Switch off"}</button></form>'
            f'<form method="post" action="/keys/remove">{hidden}<button class="danger">Remove</button></form>'
            f'</div></div>')
    if not devices:
        rows.append(f'<div class="card dim">{esc(empty)}</div>')
    return "".join(rows)


def keys_page(user: str, viewer: Session, flash: str, admin: bool, users: list[str], details=None) -> str:
    """Two tables: the devices for ssh, sudo and the screen, and the devices enrolled for the VPN (`vpn enroll`), each with its own
    passes and its own way to add one."""
    devices = store.devices(user)
    plain = [d for d in devices if not d.get("vpn_host")]
    vpn_devices = [d for d in devices if d.get("vpn_host")]
    who = ""
    if admin:
        opts = "".join(f'<option value="{esc(u)}"{" selected" if u == user else ""}>{esc(u)}</option>' for u in users)
        who = (f'<form method="get" action="/keys" class="row"><label class="dim">Account</label>'
               f'<select name="user" style="padding:8px">{opts}</select><button>Show</button></form>')
    def add_form(action: str, text: str) -> str:
        return (f'<form method="post" action="/keys/{action}"><input type="hidden" name="csrf" value="{esc(viewer.csrf)}">'
                f'<input type="hidden" name="user" value="{esc(user)}"><div class="row"><button class="primary">{esc(text)}</button></div></form>')
    note = ('<p class="dim">Changes ask your device for a fresh approval first, so nobody who only has this browser can change them.</p>')
    vpn_html = ""
    if vpn_available():
        vpn_host = grants.vpn_settings()["public_host"]
        vpn_note = ("<p class='dim'>Devices enrolled for the VPN approve each VPN login after the client certificate. "
                    "Every connection asks for fresh approval; VPN logins do not use passes or grace time. "
                    "Add a device here, or on the computer with <span class='mono'>sudo thessley-pam vpn enroll</span>.</p>")
        profiles = vpn_client_profiles(user)
        revoked_profiles = vpn_revoked_profiles(user)
        can_revoke = vpn_revocation_available()
        profile_note = ("<p class='dim'>Every download requires a fresh QR phone approval, even when you are already signed in. Each file contains "
                        "that device's private key and the VPN shared key, plus the account name and a placeholder VPN password so the client "
                        "does not prompt for them. The VPN server ignores that password. Store the profile securely and import it only on that device.</p>"
                        if profiles else
                        "<p class='dim'>No OpenVPN client certificates were found for this account. Create a separate key for each device below.</p>")
        profile_cards = "".join(
            '<div class="card"><strong>' + esc(label) + '</strong>'
            + f'<form method="post" action="/keys/vpn-profile" class="row"><input type="hidden" name="csrf" value="{esc(viewer.csrf)}">'
            + f'<input type="hidden" name="user" value="{esc(user)}"><input type="hidden" name="certificate" value="{esc(cn)}">'
            + '<button class="primary">Approve and download .ovpn profile</button></form>'
            + (f'<form method="post" action="/keys/vpn-revoke" class="row" onsubmit="return confirm(\'Revoke this certificate and disconnect this device from the VPN?\')">'
               f'<input type="hidden" name="csrf" value="{esc(viewer.csrf)}"><input type="hidden" name="user" value="{esc(user)}">'
               f'<input type="hidden" name="certificate" value="{esc(cn)}"><button class="danger">Revoke certificate</button></form>'
               if can_revoke else "") + '</div>'
            for cn, label in profiles
        )
        revoked_cards = "".join(f'<div class="card"><strong>{esc(label)}</strong> <span class="bad">Revoked</span></div>'
                                for _cn, label in revoked_profiles)
        create_profile = (
            f'<form method="post" action="/keys/vpn-create" class="row"><input type="hidden" name="csrf" value="{esc(viewer.csrf)}">'
            f'<input type="hidden" name="user" value="{esc(user)}">'
            '<label for="vpn-device-name">New device name</label>'
            '<input id="vpn-device-name" name="device" required maxlength="32" pattern="[A-Za-z0-9_.-]{1,32}" '
            'placeholder="phone or laptop" autocomplete="off">'
            '<button class="primary">Approve and create VPN key</button></form>'
            '<p class="dim">Use a different name for each device (letters, digits, dot, underscore or hyphen; up to 32 characters). '
            'Fresh phone approval creates the key and downloads its profile once. The profile contains a private key; keep it secure. '
            'Downloading an existing profile again asks for another fresh approval.</p>')
        revoke_note = ("<p class='dim'>Revoking requires a fresh phone approval. It blocks future connections and disconnects the selected device.</p>"
                       if can_revoke else
                       "<p class='dim'>Certificate revocation is unavailable until CRL enforcement and the local OpenVPN management socket are configured.</p>")
        vpn_html = ("<h2>VPN devices</h2>" + vpn_note
                    + key_cards(user, viewer, vpn_devices, details, "No device is enrolled for the VPN.")
                    + (add_form("addvpn", "Add a VPN device") if vpn_host else "")
                    + "<h2>VPN client profiles</h2>" + profile_note + profile_cards + revoke_note
                    + ("<h3>Revoked certificates</h3>" + revoked_cards if revoked_cards else "") + create_profile)
    return (flash_html(flash) + f"<h2>Keys for {esc(user)}</h2>{who}{note}"
            + key_cards(user, viewer, plain, details, "No keys are enrolled for this account.")
            + add_form("add", "Add a device") + passes_html(user, viewer, devices)
            + vpn_html)


VPN_EASYRSA = "/etc/openvpn/easy-rsa-thessley"
VPN_PKI = os.path.join(VPN_EASYRSA, "pki")
VPN_SERVER_CONFIG = "/etc/openvpn/server/thessley.conf"
VPN_CRL = os.path.join(VPN_PKI, "crl.pem")
VPN_MANAGEMENT_SOCKET = "/run/openvpn-server/thessley.mgmt"
VPN_DEVICE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")
VPN_CERT_RE = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}(?:@[A-Za-z0-9_.-]{1,32})?$")
VPN_EASYRSA_LOCK = threading.Lock()


def read_vpn_file(path: str) -> bytes:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("not a regular file")
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            return stream.read()
    finally:
        if fd >= 0:
            os.close(fd)


def vpn_certificate_status(cn: str) -> str | None:
    """Read the EasyRSA database state by the serial in a validated certificate."""
    if not VPN_CERT_RE.fullmatch(cn):
        return None
    try:
        cert = x509.load_pem_x509_certificate(read_vpn_file(os.path.join(VPN_PKI, "issued", cn + ".crt")))
        serial = cert.serial_number
        index = read_vpn_file(os.path.join(VPN_PKI, "index.txt")).decode("ascii")
    except (OSError, ValueError, UnicodeError):
        return None
    for line in index.splitlines():
        fields = line.split("\t")
        if len(fields) >= 6 and fields[0] in ("V", "R"):
            try:
                if int(fields[3], 16) == serial:
                    return fields[0]
            except ValueError:
                continue
    return None


def vpn_client_profiles(user: str) -> list[tuple[str, str]]:
    """List issued OpenVPN certificates belonging to one local account; never expose filesystem paths to the page."""
    if not USER_RE.fullmatch(user):
        return []
    issued = os.path.join(VPN_PKI, "issued")
    try:
        names = os.listdir(issued)
    except OSError:
        return []
    found = []
    for filename in names:
        if not filename.endswith(".crt"):
            continue
        cn = filename[:-4]
        if cn != user and not vpn.certificate_belongs_to(cn, user):
            continue
        if not VPN_CERT_RE.fullmatch(cn) or vpn_certificate_status(cn) != "V":
            continue
        label = cn.partition("@")[2] or "Default device"
        found.append((cn, label))
    return sorted(found, key=lambda item: (item[1].lower(), item[0]))


def vpn_revoked_profiles(user: str) -> list[tuple[str, str]]:
    """List this account's revoked certificates so their status is visible but no profile is offered."""
    if not USER_RE.fullmatch(user):
        return []
    issued = os.path.join(VPN_PKI, "issued")
    try:
        names = os.listdir(issued)
    except OSError:
        return []
    found = []
    for filename in names:
        if not filename.endswith(".crt"):
            continue
        cn = filename[:-4]
        if (cn != user and not vpn.certificate_belongs_to(cn, user)) or not VPN_CERT_RE.fullmatch(cn):
            continue
        if vpn_certificate_status(cn) == "R":
            found.append((cn, cn.partition("@")[2] or "Default device"))
    return sorted(found, key=lambda item: (item[1].lower(), item[0]))


def make_vpn_profile(user: str, cn: str) -> tuple[bytes, str] | None:
    """Build the same inline profile as vpn-new-client.sh, after checking certificate ownership and all file names."""
    if not USER_RE.fullmatch(user) or not (cn == user or vpn.certificate_belongs_to(cn, user)):
        return None
    if not VPN_CERT_RE.fullmatch(cn) or vpn_certificate_status(cn) != "V":
        return None
    try:
        cert = read_vpn_file(os.path.join(VPN_PKI, "issued", cn + ".crt"))
        key = read_vpn_file(os.path.join(VPN_PKI, "private", cn + ".key"))
        ca = read_vpn_file(os.path.join(VPN_PKI, "ca.crt"))
        tls_crypt = read_vpn_file(os.path.join(VPN_PKI, "ta.key"))
        parsed = x509.load_pem_x509_certificate(cert)
        cert_cn = parsed.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if len(cert_cn) != 1 or cert_cn[0].value != cn:
            return None
        host = grants.vpn_settings()["public_host"]
        if not host or not re.fullmatch(r"[A-Za-z0-9.:_-]{1,253}", host):
            return None
        rendered_cert = parsed.public_bytes(serialization.Encoding.PEM)
    except (OSError, ValueError):
        return None
    # The server uses the username to match the certificate to its enrolled account. The
    # password is deliberately a placeholder: QR phone approval is the login check.
    profile = (b"client\ndev tun\nproto udp\nremote " + host.encode("ascii") + b" 1194\n"
               b"remote-cert-tls server\n<auth-user-pass>\n" + user.encode("ascii") + b"\nthessley-qr-login\n</auth-user-pass>\n"
               b"auth-nocache\n"
               b"data-ciphers AES-256-GCM:CHACHA20-POLY1305\n<ca>\n" + ca.rstrip() + b"\n</ca>\n<cert>\n"
               + rendered_cert.rstrip() + b"\n</cert>\n<key>\n" + key.rstrip() + b"\n</key>\n<tls-crypt>\n"
               + tls_crypt.rstrip() + b"\n</tls-crypt>\n")
    filename = user + ("-" + cn.partition("@")[2] if "@" in cn else "") + ".ovpn"
    return profile, filename


def vpn_available() -> bool:
    """Whether this host has the enabled Thessley VPN approval service and a usable OpenVPN PKI."""
    settings = grants.vpn_settings()
    host = settings.get("public_host", "")
    required_files = (
        "/etc/openvpn/server/thessley.conf",
        "/etc/systemd/system/thessley-pam-vpn.service",
        os.path.join(VPN_EASYRSA, "easyrsa"),
        os.path.join(VPN_PKI, "ca.crt"),
        os.path.join(VPN_PKI, "ta.key"),
    )
    required_dirs = (os.path.join(VPN_PKI, "issued"), os.path.join(VPN_PKI, "private"))
    return (settings["enabled"] is True and bool(host) and bool(re.fullmatch(r"[A-Za-z0-9.:_-]{1,253}", host))
            and all(os.path.isfile(path) for path in required_files)
            and all(os.path.isdir(path) for path in required_dirs))


def vpn_revocation_available() -> bool:
    """Require server-side CRL enforcement and the root-only socket for disconnecting the selected client."""
    if not vpn_available():
        return False
    try:
        with open(VPN_SERVER_CONFIG, encoding="utf-8") as stream:
            directives = [shlex.split(line, comments=True) for line in stream]
        dirs = [os.stat(path).st_mode for path in (VPN_EASYRSA, VPN_PKI)]
        crl_mode = os.stat(VPN_CRL).st_mode
    except (OSError, UnicodeError, ValueError):
        return False
    has_crl = any(row == ["crl-verify", VPN_CRL] for row in directives)
    has_management = (any(row == ["management", VPN_MANAGEMENT_SOCKET, "unix"] for row in directives)
                      and any(row == ["management-client-user", "root"] for row in directives))
    return (has_crl and has_management and stat.S_ISREG(crl_mode) and bool(crl_mode & stat.S_IROTH)
            and all(mode & stat.S_IXOTH for mode in dirs))


def disconnect_vpn_certificate(cn: str) -> str | None:
    """Disconnect only currently connected instances for a certificate through OpenVPN's root-only management socket."""
    if not VPN_CERT_RE.fullmatch(cn):
        return None
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(4)
            conn.connect(VPN_MANAGEMENT_SOCKET)
            stream = conn.makefile("r", encoding="utf-8", newline="")
            conn.sendall(b"status 3\n")
            lines = []
            while len(lines) < 4096:
                line = stream.readline()
                if not line:
                    return None
                lines.append(line)
                if line.strip() == "END":
                    break
            if not lines or lines[-1].strip() != "END":
                return None
            client_ids = []
            for row in csv.reader(io.StringIO("".join(lines))):
                if len(row) > 10 and row[0] == "CLIENT_LIST" and row[1] == cn and row[10].isdigit():
                    client_ids.append(row[10])
            if not client_ids:
                return "offline"
            for client_id in client_ids:
                conn.sendall(f"client-kill {client_id}\n".encode("ascii"))
                while True:
                    line = stream.readline()
                    if not line or line.startswith("ERROR:"):
                        return None
                    if line.startswith("SUCCESS:"):
                        break
            return "disconnected"
    except (OSError, UnicodeError, TimeoutError):
        return None


def revoke_vpn_certificate(user: str, cn: str) -> tuple[str, str] | str:
    """Revoke one owned client certificate, refresh the enforced CRL, then disconnect only that client."""
    if not vpn_revocation_available():
        return "Certificate revocation is not configured on this VPN server. No certificate was changed."
    if not USER_RE.fullmatch(user) or not VPN_CERT_RE.fullmatch(cn):
        return "That VPN certificate is invalid. No certificate was changed."
    if cn != user and not vpn.certificate_belongs_to(cn, user):
        return "That VPN certificate does not belong to this account. No certificate was changed."
    with VPN_EASYRSA_LOCK:
        if vpn_certificate_status(cn) != "V":
            return "That VPN certificate is not active. No certificate was changed."
        try:
            serial = x509.load_pem_x509_certificate(read_vpn_file(os.path.join(VPN_PKI, "issued", cn + ".crt"))).serial_number
        except (OSError, ValueError):
            return "The VPN certificate could not be read. No certificate was changed."
        env = os.environ.copy()
        env.update({"EASYRSA_BATCH": "1", "EASYRSA_CRL_DAYS": "3650"})
        for command in (("revoke", cn), ("gen-crl",)):
            try:
                result = subprocess.run(["./easyrsa", *command], cwd=VPN_EASYRSA, env=env,
                                        stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                        timeout=90, check=False, close_fds=True)
            except (OSError, subprocess.SubprocessError) as exc:
                syslog_info(f"web VPN revocation failed for {cn}: {exc!r}")
                return "The VPN certificate could not be revoked completely. Ask an administrator to check the server."
            if result.returncode != 0:
                syslog_info(f"web VPN revocation command failed for {cn}: {result.stderr[-800:].strip()}")
                return "The VPN certificate could not be revoked completely. Ask an administrator to check the server."
        try:
            crl = x509.load_pem_x509_crl(read_vpn_file(VPN_CRL))
            if vpn_certificate_status(cn) != "R" or not any(item.serial_number == serial for item in crl):
                return "The VPN certificate was marked revoked, but the CRL update did not verify. Contact an administrator."
            os.chmod(VPN_CRL, 0o644)
        except (OSError, ValueError):
            return "The VPN certificate was marked revoked, but the CRL could not be verified. Contact an administrator."
        disconnected = disconnect_vpn_certificate(cn)
        syslog_info(f"web revoked VPN certificate {cn} for {user}; active connection state: {disconnected or 'unknown'}")
        return cn, disconnected or "disconnect-failed"


def create_vpn_client_profile(user: str, device: str) -> tuple[bytes, str] | str:
    """Issue one account@device certificate and return its inline profile for the approved one-time download."""
    if not vpn_available():
        return "The VPN is not available on this computer. No VPN key was created."
    if not USER_RE.fullmatch(user) or not VPN_DEVICE_RE.fullmatch(device):
        return "The account or device name is invalid. No VPN key was created."
    try:
        pwd.getpwnam(user)
    except KeyError:
        return "That account does not exist on this computer. No VPN key was created."
    host = grants.vpn_settings().get("public_host", "")
    if not host or not re.fullmatch(r"[A-Za-z0-9.:_-]{1,253}", host):
        return "The VPN public host is not configured. No VPN key was created."
    if not os.path.isfile(os.path.join(VPN_EASYRSA, "easyrsa")) or not os.path.isdir(os.path.join(VPN_PKI, "issued")):
        return "The VPN certificate authority is unavailable. No VPN key was created."

    cn = user + "@" + device
    cert_path = os.path.join(VPN_PKI, "issued", cn + ".crt")
    key_path = os.path.join(VPN_PKI, "private", cn + ".key")
    with VPN_EASYRSA_LOCK:
        if os.path.lexists(cert_path) or os.path.lexists(key_path):
            return "That device name already has a VPN key. Choose a different name."
        env = os.environ.copy()
        env.update({"EASYRSA_BATCH": "1", "EASYRSA_ALGO": "ec", "EASYRSA_CURVE": "prime256v1",
                    "EASYRSA_CERT_EXPIRE": "825"})
        try:
            result = subprocess.run(["./easyrsa", "build-client-full", cn, "nopass"], cwd=VPN_EASYRSA,
                                    env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, timeout=90, check=False, close_fds=True)
        except (OSError, subprocess.SubprocessError):
            return "The VPN certificate could not be created. No profile was downloaded. Check the server logs."
        if result.returncode != 0:
            return "The VPN certificate could not be created. No profile was downloaded. Check the server logs."
        package = make_vpn_profile(user, cn)
        if package is None:
            return "The VPN key was created, but its profile could not be prepared. Ask an administrator to check the VPN setup."
        return package


PASS_NAMES = {"sshd": "ssh login", "sudo": "sudo", "gdm-thessley": "screen login", "gdm-password": "screen login", "openvpn": "VPN login"}


def passes_html(user: str, viewer: Session, devices: list[dict]) -> str:
    """The approvals that let this account in without asking its device again (the 4 h passes), each with a button that ends it.
    Ending a pass only takes access away, so it needs no fresh approval; the next login asks the device again."""
    labels = {d["credential_id"]: d.get("label", "") for d in devices}
    items = [p for p in grants.passes_of(user) if p.get("service") not in grants.NO_GRACE]   # the VPN never has one
    hidden = f'<input type="hidden" name="csrf" value="{esc(viewer.csrf)}"><input type="hidden" name="user" value="{esc(user)}">'
    rows = []
    for p in items:
        what = PASS_NAMES.get(p.get("service", ""), p.get("service", "?"))
        by = labels.get(p.get("credential", ""), "") or "a removed device"
        rows.append(
            f'<div class="card"><strong>{esc(what)}</strong> from {esc(p.get("rhost", ""))} '
            f'<span class="dim">· approved by {esc(by)} · {esc(grants.remaining(p))} left</span>'
            f'<form method="post" action="/passes/end" class="row">{hidden}'
            f'<input type="hidden" name="service" value="{esc(p.get("service", ""))}">'
            f'<input type="hidden" name="rhost" value="{esc(p.get("rhost", ""))}"><button class="danger">End this pass</button></form></div>')
    if not rows:
        body = '<div class="card dim">No pass is active: every login asks your device.</div>'
    else:
        body = "".join(rows) + (f'<form method="post" action="/passes/end" class="row">{hidden}'
                                '<input type="hidden" name="all" value="1"><button class="danger">End all passes</button></form>')
    return ("<h2>Passes</h2><p class='dim'>After one approval, the same account from the same address is let in without asking "
            "your device again, for a few hours. End a pass to make the next login ask again.</p>" + body)


def key_details_html(rows: list[tuple[str, str]]) -> str:
    if not rows:
        return ""
    body = "".join(f"<div class='key-detail-row'><dt>{esc(k)}</dt><dd>{esc(v)}</dd></div>" for k, v in rows)
    return f"<details class='key-details'><summary class='link'>Details</summary><dl class='key-detail-list'>{body}</dl></details>"


def log_page(rows: list[tuple[str, str]], who: str, page_number: int = 1, everyone: bool = False) -> str:
    page_size = 20
    total = len(rows)
    page_count = max(1, (total + page_size - 1) // page_size)
    page_number = max(1, min(page_number, page_count))
    start = (page_number - 1) * page_size
    visible = rows[start:start + page_size]

    def pager() -> str:
        query = "?all=1" if everyone else ""
        separator = "&" if query else "?"
        previous = (f'<a class="btn small" href="/log{query}{separator}page={page_number - 1}" aria-label="Previous page">Previous</a>'
                    if page_number > 1 else '<a class="btn small" aria-disabled="true" tabindex="-1">Previous</a>')
        following = (f'<a class="btn small" href="/log{query}{separator}page={page_number + 1}" aria-label="Next page">Next</a>'
                     if page_number < page_count else '<a class="btn small" aria-disabled="true" tabindex="-1">Next</a>')
        status = (f"{start + 1}–{min(start + page_size, total)} of {total} · Page {page_number} of {page_count}"
                  if total else "Page 1 of 1")
        return f'<nav class="pagination" aria-label="Activity pages">{previous}<span class="page-status">{status}</span>{following}</nav>'

    def timestamp(value: str) -> str:
        date, separator, clock = value.partition(" ")
        if not separator:
            return esc(value)
        return (f"<time class='activity-time' datetime='{esc(date)}T{esc(clock)}'>"
                f"<span class='activity-time-date'>{esc(date)}</span><span class='activity-time-clock'>{esc(clock)}</span></time>")

    body = "".join(f"<tr><td class='mono activity-time-cell'>{timestamp(t)}</td><td>{esc(s)}</td></tr>" for t, s in visible)
    return (f"<h2>Activity for {esc(who)}</h2><p class='dim'>The newest first. Approvals, refusals, passes and enrolments "
            f"recorded on this computer.</p>{pager()}<div class='card'><div class='table-wrap'><table>{body or '<tr><td class=dim>Nothing recorded yet.</td></tr>'}</table></div></div>{pager()}")


def admin_page(viewer: Session, flash: str) -> str:
    sshd_grace = grants.grace_hours("sshd")
    on = lambda flag: "on" if flag else "off"  # noqa: E731
    hidden = f'<input type="hidden" name="csrf" value="{esc(viewer.csrf)}">'

    def toggle(name: str, label: str, state: bool, explain: str) -> str:
        return (f'<div class="card"><strong>{esc(label)}</strong>: <span class="{"ok" if state else "bad"}">{on(state)}</span>'
                f'<div class="dim">{esc(explain)}</div><form method="post" action="/admin/set" class="row">{hidden}'
                f'<input type="hidden" name="name" value="{esc(name)}">'
                f'<button name="value" value="{"off" if state else "on"}">Switch {"off" if state else "on"}</button></form></div>')

    ssh_source_modes = grants.ssh_source_modes()
    try:
        ssh_source_ips = grants.ssh_allowed_ips()
        ssh_source_error = "" if "invalid" not in ssh_source_modes else "The saved SSH source policy is invalid; SSH logins fail closed until you save a valid option."
    except (TypeError, ValueError):
        ssh_source_ips = []
        ssh_source_error = "The saved SSH source policy is malformed; SSH logins fail closed until you save a valid option."
    local_networks = machine.interface_networks("local")
    vpn_networks = machine.interface_networks("vpn")
    if "invalid" in ssh_source_modes:
        ssh_source_modes = ["any"]
    ssh_source_ip_setting = (
        '<div class="card"><strong>Allowed source networks for Thessley SSH logins</strong>'
        + (f'<p class="bad">{esc(ssh_source_error)}</p>' if ssh_source_error else "")
        + '<div class="dim">Check one or more source types. All IPs is exclusive. Clients outside the selected networks are refused before phone approval. '
          'This applies to accounts using the Thessley SSH controls. The four-hour approval pass remains tied to its original client IP.</div>'
        + f'<form method="post" action="/admin/set" class="ssh-source-form">{hidden}'
        + '<input type="hidden" name="name" value="ssh_source_policy">'
        + '<div class="ssh-source-options">'
        + f'<label><input id="ssh-source-any" type="checkbox" name="all_ips" value="on" '
          f'{"checked" if ssh_source_modes == ["any"] else ""} '
          'onchange="if(this.checked)document.querySelectorAll(\'.ssh-source-restrict\').forEach(x=>x.checked=false)"> All IPs</label>'
        + f'<label><input class="ssh-source-restrict" type="checkbox" name="local" value="on" '
          f'{"checked" if "local" in ssh_source_modes else ""} '
          'onchange="if(this.checked)document.getElementById(\'ssh-source-any\').checked=false"> Local networks</label>'
        + f'<label><input class="ssh-source-restrict" type="checkbox" name="vpn" value="on" '
          f'{"checked" if "vpn" in ssh_source_modes else ""} '
          'onchange="if(this.checked)document.getElementById(\'ssh-source-any\').checked=false"> VPN networks</label>'
        + f'<label><input id="ssh-source-custom-check" class="ssh-source-restrict" type="checkbox" name="custom" value="on" '
          f'{"checked" if "custom" in ssh_source_modes else ""} '
          'onchange="if(this.checked)document.getElementById(\'ssh-source-any\').checked=false"> Chosen list</label></div>'
        + '<label for="ssh-source-custom">Allowed IP addresses or CIDR ranges for Chosen list</label>'
        + '<div id="ssh-source-custom">'
        + f'<input type="text" name="addresses" value="{esc(", ".join(ssh_source_ips))}" '
          'placeholder="Example: 203.0.113.7, 198.51.100.0/24" '
          'aria-label="Allowed SSH client IP addresses or CIDR ranges"></div>'
        + f'<p class="dim">Detected local: {esc(", ".join(local_networks) or "none")}. '
          f'Detected VPN: {esc(", ".join(vpn_networks) or "none active")}. A source type with no active interface currently contributes no allowed addresses; other checked types still work.</p>'
        + '<button>Save SSH source IPs</button></form></div>')
    qr_group = ssh_qr_group_members()
    account_rows = []
    for username in interactive_accounts():
        try:
            devices = store.devices(username)
            active_count = sum(not d.get("disabled") for d in devices)
        except (OSError, KeyError, ValueError):
            devices, active_count = [], 0
        phone_state = (f"{active_count} active phone{'s' if active_count != 1 else ''}"
                       if active_count else "No active phone · first enrollment needed")
        blocked = grants.ssh_user_is_blocked(username)
        ssh_state = ("Blocked at the SSH server" if blocked else
                     "SSH QR policy applies" if username in qr_group else "Standard SSH authentication")
        ssh_controls = ""
        if username in qr_group:
            mode = grants.ssh_user_login_mode(username)
            policy = grants.ssh_user_login_policy(username)
            blocked = blocked or policy["blocked"]
            policy["blocked"] = blocked
            ssh_state = "Blocked at the SSH server" if blocked else "SSH QR policy applies"
            ssh_controls = (
                f'<form method="post" action="/admin/set" class="row ssh-user-policy-form">{hidden}'
                '<input type="hidden" name="name" value="ssh_user_policy">'
                f'<input type="hidden" name="user" value="{esc(username)}">'
                f'<label><input type="checkbox" name="inherit" value="on"{" checked" if mode == "inherit" else ""}> Use the computer-wide policy</label>'
                '<p class="dim">Change any path checkbox below to save a per-user policy; this automatically turns off the computer-wide option.</p>'
                '<div class="ssh-policy-options">'
                f'<label><input type="checkbox" name="qr_only" value="on"{" checked" if policy["qr_only"] else ""}> <span>QR-only login</span></label>'
                f'<label><input type="checkbox" name="key_qr" value="on"{" checked" if policy["key_qr"] else ""}> <span>SSH key + QR approval</span></label>'
                f'<label><input type="checkbox" name="key_password" value="on"{" checked" if policy["key_password"] else ""}> <span>SSH key + account password</span></label>'
                f'<label><input type="checkbox" name="blocked" value="on"{" checked" if policy["blocked"] else ""}> <span>Block SSH for this account</span></label>'
                '</div>'
                f'<button>Save SSH access for {esc(username)}</button></form>')
        else:
            ssh_controls = (
                f'<form method="post" action="/admin/set" class="row">{hidden}'
                '<input type="hidden" name="name" value="ssh_user_policy">'
                f'<input type="hidden" name="user" value="{esc(username)}">'
                f'<label><input type="checkbox" name="blocked" value="on"{" checked" if blocked else ""}> '
                '<span>Block SSH for this account</span></label>'
                '<p class="dim">This works for accounts outside <span class="mono">thessley-ssh</span> too. '
                'It blocks new SSH logins at the SSH server, for every authentication method; existing sessions stay open.</p>'
                f'<button>Save SSH access for {esc(username)}</button></form>')
        account_rows.append(
            f'<div class="card"><strong>{esc(username)}</strong>'
            f'<div class="dim">SSH: {esc(ssh_state)}</div><div class="dim">Phone: {esc(phone_state)}</div>'
            + ssh_controls +
            f'<div class="row"><a class="btn small" href="/keys?user={esc(username)}">Manage devices / enroll</a></div></div>')
    users_section = (
        '<section class="admin-users"><h2>Users and first enrollment</h2>'
        '<p class="dim">Choose an account to review its enrolled phones or add its first one. On the account page, select '
        '<strong>Add a device</strong>, scan the QR or open the link, then compare and confirm the two codes. '
        'The administrator signed in here must approve the change on their own phone.</p>'
        '<p class="dim">QR login choices apply to members of <span class="mono">thessley-ssh</span>. '
        'Per-user settings override the computer-wide SSH policy for group members. “Block SSH” applies at the SSH server to any account, '
        'including accounts outside that group, and denies new connections using any authentication method. Existing sessions stay open. '
        'QR-only requires sshd to permit keyboard-interactive login without a public key; '
        'if sshd requires <span class="mono">publickey,keyboard-interactive:pam</span>, use SSH key + QR instead.</p>'
        + ("".join(account_rows) or '<div class="card dim">No interactive accounts found.</div>')
        + '</section>'
        '<script nonce="{NONCE}">'
        'document.querySelectorAll(".ssh-user-policy-form").forEach(function(form){'
        'var inherit=form.querySelector("[name=inherit]");'
        'var blocked=form.querySelector("[name=blocked]");'
        'var paths=form.querySelectorAll("[name=qr_only],[name=key_qr],[name=key_password]");'
        'paths.forEach(function(box){box.addEventListener("change",function(){'
        'inherit.checked=false;if(box.checked)blocked.checked=false;'
        '});});'
        'blocked.addEventListener("change",function(){inherit.checked=false;'
        'if(blocked.checked)paths.forEach(function(box){box.checked=false;});'
        '});'
        '});'
        '</script>')
    ssh_policy = grants.ssh_login_policy()
    ssh_policy = (f'<div class="card"><strong>SSH login policy</strong>'
                  '<div class="dim">Applies only to accounts in the thessley-ssh group. '
                  'Changes are applied to the next SSH login.</div>'
                  f'<form method="post" action="/admin/set">{hidden}'
                  '<input type="hidden" name="name" value="ssh_policy">'
                  '<div class="ssh-policy-options">'
                  f'<label><input type="checkbox" name="qr_only" value="on"{" checked" if ssh_policy["qr_only"] else ""}> <span>QR-only login (no key or password on this path)</span></label>'
                  f'<label><input type="checkbox" name="key_qr" value="on"{" checked" if ssh_policy["key_qr"] else ""}> <span>SSH key + QR phone approval</span></label>'
                  f'<label><input type="checkbox" name="key_password" value="on"{" checked" if ssh_policy["key_password"] else ""}> <span>Allow SSH key + account password (recovery if QR is unavailable)</span></label>'
                  '</div>'
                  '<button>Save SSH policy</button></form>'
                  '<div class="dim"><p>Each checked box enables a complete alternative login path (OR). A login only needs to complete one selected path.</p>'
                  '<ul><li><strong>QR-only:</strong> no SSH key or account password is needed. A fresh phone approval starts the configured SSH pass; until it expires, eligible logins from the configured IP scope do not ask again. Set the pass to 0 to ask every time.</li>'
                  '<li><strong>SSH key + QR:</strong> provide an SSH key, then approve on the phone. The configured approval pass may apply.</li>'
                  '<li><strong>SSH key + password:</strong> provide an SSH key and the account password. This route always requires a key.</li></ul>'
                  '<p><strong>Examples:</strong> QR-only permits keyless QR logins and then uses the configured pass duration and IP scope. SSH key + QR together with SSH key + password tries phone approval first; '
                  'the password route can recover if no phone is enrolled, approval is denied, or it times out. QR-only together with SSH key + password '
                  'permits keyless QR logins or key + password logins.</p></div></div>')
    grace = (f'<div class="card"><strong>How long one approval counts for ssh</strong>: {sshd_grace:g} h'
             f'<div class="dim">After one approval, logins from the configured IP scope need no new one for this long. 0 means every login asks.</div>'
             f'<form method="post" action="/admin/set" class="row">{hidden}<input type="hidden" name="name" value="grace">'
             f'<input type="text" name="value" value="{sshd_grace:g}" style="width:6rem"> hours <button>Change</button></form></div>')
    session = grants.web_settings()["session_minutes"]
    web_settings = grants.web_settings()
    grace += (f'<div class="card"><strong>Stay signed in to this page</strong>: {session} minutes without activity'
              f'<div class="dim">After this long without clicking anything you are signed out (always after 8 hours). '
              f'Applies from the next sign-in. 1 to 240 minutes.</div>'
              f'<form method="post" action="/admin/set" class="row">{hidden}<input type="hidden" name="name" value="session">'
              f'<input type="text" name="value" value="{session}" style="width:6rem"> minutes <button>Change</button></form></div>')
    limits = (f'<div class="card"><strong>Web service resource limits</strong>'
              f'<div class="dim">Maximum simultaneous web requests and remembered source-IP rate-limit buckets. '
              f'When the bucket limit is reached, old buckets are expired/evicted. Current: {web_settings["max_connections"]} connections, '
              f'{web_settings["rate_limit_entries"]} IPs.</div>'
              f'<form method="post" action="/admin/set" class="row">{hidden}<input type="hidden" name="name" value="web_limits">'
              f'<input type="number" name="connections" min="4" max="256" value="{web_settings["max_connections"]}" aria-label="Maximum concurrent connections"> connections '
              f'<input type="number" name="buckets" min="64" max="100000" value="{web_settings["rate_limit_entries"]}" aria-label="Rate limit entries"> IP buckets '
              f'<button>Save limits</button></form></div>')
    web_host = "127.0.0.1" if web_settings["localhost_only"] else (web_settings["listen"] or machine.lan_ip())
    if web_host in ("0.0.0.0", "::"):
        web_host = machine.lan_ip()
    localhost_setting = toggle(
        "localhost_only", "Admin page available only on 127.0.0.1", web_settings["localhost_only"],
        (f"When on, only this computer can connect at https://127.0.0.1:{web_settings['port']}/. "
         f"When off, it listens at https://{web_host}:{web_settings['port']}/. Changing this restarts the web listener; "
         "turning it on disconnects browsers on other computers.")
    )
    journal_info = ('<div class="card"><strong>Linux log retention</strong><div class="dim">Thessley activity is sent to the system journal, '
                    'which rotates according to the host journald limits. Changing those limits affects other system services, '
                    'so configure retention in the host journal settings rather than here.</div></div>')
    policy_failure = grants.ssh_policy_failure_mode()
    failure = (f'<div class="card"><strong>SSH policy file recovery</strong><div class="dim">If the SSH policy file is missing, malformed, or unsafe, '
               f'current behavior is {"fail closed and require key + QR" if policy_failure == "closed" else "allow key + account password recovery"}. '
               'Strict mode can lock out SSH if phone approval is unavailable; keep a tested recovery path.</div>'
               f'<form method="post" action="/admin/set" class="row">{hidden}<input type="hidden" name="name" value="ssh_policy_failure">'
               f'<select name="value"><option value="fallback"{" selected" if policy_failure == "fallback" else ""}>Allow key + password recovery</option>'
               f'<option value="closed"{" selected" if policy_failure == "closed" else ""}>Fail closed; require key + QR</option></select> '
               '<button>Save recovery behavior</button></form></div>')
    return (flash_html(flash) + "<h2>Settings for this computer</h2>"
            "<p class='dim'>Only administrators see this page. Every change asks your device for a fresh approval.</p>"
            + users_section + ssh_policy + failure + limits + localhost_setting + journal_info + grace
            + ssh_source_ip_setting
            + toggle("self_enroll", "Users may add their own device", grants.self_enroll_allowed(),
                     "thessley-pam enroll-me: the first device freely, more with an approval.")
            + toggle("show_link", "Text links in approvals", store.show_link(),
                     "A line “Link: thessleypam://…” above each QR code, for devices and computers that cannot scan.")
            + f"<p class='dim'>Passes held right now: {esc(len(grants.all_passes()))}.</p>")


# ---- HTTP ------------------------------------------------------------------------------------------------------

def make_handler(app: WebApp):
    class Handler(BaseHTTPRequestHandler):
        server_version = "ThessleyWeb"
        sys_version = ""
        timeout = 30

        def log_message(self, fmt, *args):  # nothing about requests in the logs: names and paths are not worth keeping
            pass

        # -- helpers
        def ip(self) -> str:
            return self.client_address[0]

        def cookies(self) -> dict:
            out = {}
            for part in (self.headers.get("Cookie") or "").split(";"):
                if "=" in part:
                    k, v = part.strip().split("=", 1)
                    out[k] = v
            return out

        def session(self) -> Session | None:
            return app.session(self.cookies().get("thessley_session"))

        def form(self) -> dict:
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0
            if length < 0 or length > MAX_BODY:
                return {}
            raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
            return {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()}

        def send(self, status: int, body: bytes, ctype: str = "text/html; charset=utf-8", extra: list[tuple[str, str]] | None = None,
                 nonce: str | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            script = f"script-src 'nonce-{nonce}'" if nonce else "script-src 'none'"
            self.send_header("Content-Security-Policy",
                             f"default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; "
                             f"form-action 'self'; frame-ancestors 'none'; base-uri 'none'; {script}")
            for k, v in extra or []:
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def html(self, status: int, title: str, body: str, session: Session | None = None, extra=None) -> None:
            nonce = secrets.token_urlsafe(12)
            admin = bool(session and is_admin(session.user))
            body = body.replace("{NONCE}", nonce)
            self.send(status, page(title, body, nonce, session, admin).encode(), extra=extra, nonce=nonce)

        def redirect(self, url: str, extra=None) -> None:
            self.send_response(303)
            self.send_header("Location", url)
            self.send_header("Content-Length", "0")
            self.send_header("Cache-Control", "no-store")
            for k, v in extra or []:
                self.send_header(k, v)
            self.end_headers()

        def json(self, obj: dict, extra=None) -> None:
            self.send(200, json.dumps(obj).encode(), "application/json", extra)

        def cookie(self, name: str, value: str, max_age: int | None = None) -> tuple[str, str]:
            age = f"; Max-Age={max_age}" if max_age is not None else ""
            return ("Set-Cookie", f"{name}={value}; HttpOnly; Secure; SameSite=Strict; Path=/{age}")

        def need_session(self) -> Session | None:
            s = self.session()
            if s is None:
                self.redirect("/")
            return s

        def csrf_ok(self, s: Session, data: dict) -> bool:
            ok = hmac.compare_digest(str(data.get("csrf", "")), s.csrf)
            if not ok:
                self.html(400, "Refused", flash_html("That form was not valid (it may be old). Go back and try again."), s)
            return ok

        def flow_for(self, fid: str, s: Session | None) -> Flow | None:
            """A flow, only for the browser that started it: the wait cookie (sign-in) or the signed-in account (others)."""
            f = app.flow(fid)
            if f is None:
                return None
            if f.kind == "login":
                return f if hmac.compare_digest(self.cookies().get("thessley_wait", ""), f.secret) else None
            return f if s is not None and s.user == f.owner else None

        # -- routes
        def do_GET(self):  # noqa: N802
            path = urlsplit(self.path)
            route, query = path.path, {k: v[0] for k, v in parse_qs(path.query).items()}
            s = self.session()
            if route == "/":
                return self.redirect("/keys") if s else self.html(200, "Sign in", login_page())
            m = re.fullmatch(r"/wait/([0-9a-f]{32})", route)
            if m:
                f = self.flow_for(m.group(1), s)
                if f is None:
                    return self.html(404, "Not found", flash_html("That request is no longer here. Start again."), s)
                heading = "Approve the sign-in" if f.kind == "login" else f"Approve: {f.description}"
                note = (f"Scan the code with the Thessley Passkey app, or open the link. You have {WEB_WAIT // 60} minutes." if f.kind != "enroll"
                        else "Scan the code with the new device's Thessley Passkey app, or open the link on the new app.")
                return self.html(200, heading, wait_page(f, "{NONCE}", s, heading, note), s)
            m = re.fullmatch(r"/status/([0-9a-f]{32})", route)
            if m:
                return self.status(m.group(1), s, query.get("qr") == "1")
            m = re.fullmatch(r"/qr/([0-9a-f]{32})\.svg", route)
            if m:
                f = self.flow_for(m.group(1), s)
                if f is None or not f.link:
                    return self.send(404, b"", "text/plain")
                try:
                    return self.send(200, app.qr(f.link), "image/svg+xml")
                except (OSError, subprocess.SubprocessError):
                    return self.send(500, b"", "text/plain")
            m = re.fullmatch(r"/enroll/([0-9a-f]{32})", route)
            if m:
                s = self.need_session()
                if s is None:
                    return
                f = self.flow_for(m.group(1), s)
                if f is None or f.kind != "enroll":
                    return self.html(404, "Not found", flash_html("That request is no longer here."), s)
                return self.html(200, "Add a device", wait_page(f, "{NONCE}", s, "Add a device",
                                 "Scan the code with the new device's Thessley Passkey app, or open the link on the new app."), s)
            m = re.fullmatch(r"/keys/vpn-profile/([A-Za-z0-9_-]{40,50})", route)
            if m:
                s = self.need_session()
                if s is None:
                    return
                if not vpn_available():
                    return self.html(404, "Not found", flash_html("The VPN is not available on this computer."), s)
                package = app.take_vpn_download(m.group(1), s.user)
                if package is None:
                    return self.html(404, "Not found", flash_html("This approved download link is expired or already used."), s)
                body, filename = package
                return self.send(200, body, "application/x-openvpn-profile; charset=utf-8",
                                 [("Content-Disposition", f'attachment; filename="{filename}"')])
            if route == "/keys":
                s = self.need_session()
                if s is None:
                    return
                target = app.target(s, query.get("user"))
                if target is None:
                    return self.html(403, "Not allowed", flash_html("You can only see your own keys."), s)
                flash, s.flash = s.flash, ""
                users = interactive_accounts() if is_admin(s.user) else []
                usage = app.key_usage()
                return self.html(200, "Your keys", keys_page(target, s, flash, is_admin(s.user), users,
                                                              lambda d: app.key_details(target, d, usage)), s)
            if route == "/log":
                s = self.need_session()
                if s is None:
                    return
                everyone = is_admin(s.user) and query.get("all") == "1"
                rows = app.activity(None if everyone else s.user)
                page_text = query.get("page", "1")
                page_number = int(page_text) if page_text.isdigit() else 1
                return self.html(200, "Activity", log_page(rows, "everyone" if everyone else s.user,
                                                              page_number, everyone), s)
            if route == "/admin":
                s = self.need_session()
                if s is None:
                    return
                if not is_admin(s.user):
                    return self.html(403, "Not allowed", flash_html("Only administrators can open this page."), s)
                flash, s.flash = s.flash, ""
                return self.html(200, "Admin", admin_page(s, flash), s)
            self.html(404, "Not found", flash_html("There is nothing here."), s)

        def do_POST(self):  # noqa: N802
            route = urlsplit(self.path).path
            data = self.form()
            s = self.session()
            if route == "/login":
                user = (data.get("user") or "").strip().lower()
                if not app.rate_ok(self.ip()):
                    return self.html(429, "Slow down", login_page("Too many sign-in requests from this address. Wait a few minutes."))
                flow = app.start_login(user, self.ip())
                if flow is None:  # the same words for an unknown account and one with no key: no hint which it is
                    return self.html(200, "Sign in", login_page("That account cannot sign in here: it has no key enrolled, or it does not exist."))
                return self.redirect(f"/wait/{flow.id}", [self.cookie("thessley_wait", flow.secret, 600)])
            if route == "/logout":
                if s and hmac.compare_digest(str(data.get("csrf", "")), s.csrf):
                    app.drop_session(s.token)
                return self.redirect("/", [self.cookie("thessley_session", "", 0)])
            if s is None:
                return self.redirect("/")
            if not self.csrf_ok(s, data):
                return
            m = re.fullmatch(r"/enroll/([0-9a-f]{32})/confirm", route)
            if m:
                f = self.flow_for(m.group(1), s)
                if f is None or f.kind != "enroll" or f.state != "confirm":
                    return self.redirect("/keys")
                f.answer = data.get("answer") == "yes"
                f.answered.set()
                return self.redirect(f"/enroll/{f.id}")
            if route == "/keys/vpn-revoke":
                if not vpn_available() or not vpn_revocation_available():
                    return self.html(404, "Not found", flash_html("VPN certificate revocation is not available on this computer."), s)
                target = app.target(s, data.get("user"))
                if target is None:
                    return self.html(403, "Not allowed", flash_html("You can only revoke certificates for your account."), s)
                certificate = data.get("certificate", "")
                if certificate not in {cn for cn, _label in vpn_client_profiles(target)}:
                    return self.html(404, "Not found", flash_html("That active VPN certificate is unavailable."), s)

                def revoke_certificate():
                    result = revoke_vpn_certificate(target, certificate)
                    if isinstance(result, str):
                        return "/keys", result
                    cn, connection_state = result
                    device = cn.partition("@")[2] or "Default device"
                    if connection_state == "disconnected":
                        message = f"Revoked the certificate for {device} and disconnected its active VPN session."
                    elif connection_state == "offline":
                        message = f"Revoked the certificate for {device}. It had no active VPN session."
                    else:
                        message = (f"Revoked the certificate for {device}, but could not confirm whether its current VPN session "
                                   "was disconnected. Disconnect that device manually if it is still online.")
                    return "/keys", message

                return self.start_change(s, f"revoking VPN certificate {certificate} for {target}", revoke_certificate,
                                        SERVICE_VPN_REVOKE)
            if route == "/keys/vpn-create":
                if not vpn_available():
                    return self.html(404, "Not found", flash_html("The VPN is not available on this computer."), s)
                target = app.target(s, data.get("user"))
                if target is None:
                    return self.html(403, "Not allowed", flash_html("You can only create VPN profiles for your account."), s)
                device = (data.get("device") or "").strip()
                if not VPN_DEVICE_RE.fullmatch(device):
                    return self.html(400, "Invalid device name", flash_html("Use 1 to 32 letters, digits, dots, underscores or hyphens."), s)
                certificate = target + "@" + device
                if any(cn == certificate for cn, _label in vpn_client_profiles(target)):
                    return self.html(409, "Device already exists", flash_html("That device name already has a VPN key. Choose a different name."), s)

                def create_and_download():
                    result = create_vpn_client_profile(target, device)
                    if isinstance(result, str):
                        return "/keys", result
                    body, filename = result
                    token = app.issue_vpn_download(s.user, body, filename)
                    if token is None:
                        return "/keys", "The VPN key was created, but its download could not be queued. Use its profile card to request a fresh approved download."
                    return f"/keys/vpn-profile/{token}", "Phone approved; the new VPN key profile download is starting."

                return self.start_change(s, f"creating a VPN key for {target} on {device}", create_and_download,
                                        SERVICE_VPN_DOWNLOAD)
            if route == "/keys/vpn-profile":
                if not vpn_available():
                    return self.html(404, "Not found", flash_html("The VPN is not available on this computer."), s)
                target = app.target(s, data.get("user"))
                if target is None:
                    return self.html(403, "Not allowed", flash_html("You can only download profiles for your account."), s)
                certificate = data.get("certificate", "")
                if certificate not in {cn for cn, _label in vpn_client_profiles(target)}:
                    return self.html(404, "Not found", flash_html("That VPN profile is unavailable."), s)

                def prepare_download():
                    result = make_vpn_profile(target, certificate)
                    if result is None:
                        return "/keys", "That VPN profile is no longer available."
                    body, filename = result
                    token = app.issue_vpn_download(s.user, body, filename)
                    if token is None:
                        return "/keys", "Too many approved downloads are waiting. Try again in a moment."
                    return f"/keys/vpn-profile/{token}", "Phone approved; the VPN profile download is starting."

                return self.start_change(s, f"downloading a VPN profile for {target}", prepare_download,
                                        SERVICE_VPN_DOWNLOAD)
            if route.startswith("/keys/"):
                return self.keys_action(route[len("/keys/"):], data, s)
            if route == "/passes/end":
                return self.passes_end(data, s)
            if route == "/admin/set":
                if not is_admin(s.user):
                    return self.html(403, "Not allowed", flash_html("Only administrators can change settings."), s)
                return self.admin_action(data, s)
            self.html(404, "Not found", flash_html("There is nothing here."), s)

        def start_change(self, s: Session, description: str, action, service: str = SERVICE_CHANGE) -> None:
            flow = app.start_change(s, self.ip(), description, action, service)
            if flow is None:
                return self.html(503, "Busy", flash_html("Could not start the approval (too many at once, or no key is enrolled for you)."), s)
            self.redirect(f"/wait/{flow.id}", [self.cookie("thessley_wait", flow.secret, 600)])

        def keys_action(self, action: str, data: dict, s: Session) -> None:
            target = app.target(s, data.get("user"))
            cred = data.get("cred", "")
            if target is None:
                return self.html(403, "Not allowed", flash_html("You can only change your own keys."), s)
            if action == "add":
                return self.start_change(s, f"adding a device for {target}", app.change_begin_enroll(target, s.user), SERVICE_DEVICE)
            if action == "addvpn":
                if not vpn_available():
                    return self.html(404, "Not found", flash_html("The VPN is not available on this computer."), s)
                host = grants.vpn_settings()["public_host"]
                if not host:
                    return self.html(400, "Not possible", flash_html("Set the VPN's public host first: sudo thessley-pam vpn public-host NAME"), s)
                return self.start_change(s, f"adding a VPN device for {target}", app.change_begin_enroll(target, s.user, host), SERVICE_DEVICE)
            known = {d["credential_id"]: d for d in store.devices(target)}
            if not CRED_RE.match(cred) or cred not in known:
                return self.html(404, "Not found", flash_html("No such key."), s)
            label = known[cred].get("label", "")
            if action == "rename":
                new = (data.get("label") or "").strip()
                if not cli.LABEL.match(new):
                    return self.html(400, "Not valid", flash_html("Use 1 to 64 letters, digits, spaces and . , ' ( ) + - in the name."), s)
                return self.start_change(s, f"renaming {label} to {new}", app.change_rename(target, cred, new))
            if action in ("disable", "enable"):
                return self.start_change(s, f"{'switching off' if action == 'disable' else 'switching on'} {label} for {target}",
                                         app.change_disable(target, cred, action == "disable"))
            if action == "remove":
                return self.start_change(s, f"removing {label} from {target}", app.change_remove(target, cred))
            return self.html(404, "Not found", flash_html("There is nothing here."), s)

        def passes_end(self, data: dict, s: Session) -> None:
            """End one pass, or all of an account's. Only takes access away, so no fresh approval is asked."""
            target = app.target(s, data.get("user"))
            if target is None:
                return self.html(403, "Not allowed", flash_html("You can only end your own passes."), s)
            if data.get("all"):
                ended = grants.revoke(username=target)
            else:
                service, rhost = str(data.get("service", "")), str(data.get("rhost", ""))
                if not service or not rhost or len(service) > 64 or len(rhost) > 64:
                    return self.html(400, "Not valid", flash_html("No such pass."), s)
                ended = grants.revoke_one(target, service, rhost)
            app.log(f"web page: {s.user} ended {ended} pass(es) of {target}")
            s.flash = (f"Ended {ended} pass{'es' if ended != 1 else ''}. The next login asks your device again." if ended
                       else "That pass had already ended.")
            return self.redirect("/keys" if target == s.user else f"/keys?user={target}")

        def admin_action(self, data: dict, s: Session) -> None:
            name, value = data.get("name", ""), (data.get("value") or "").strip()
            if name == "ssh_policy":
                qr_only = data.get("qr_only") == "on"
                key_qr = data.get("key_qr") == "on"
                key_password = data.get("key_password") == "on"
                if not (qr_only or key_qr or key_password):
                    return self.html(400, "Not valid", flash_html("Select at least one SSH login path."), s)
                self.start_change(s, "changing the SSH login policy",
                                  app.change_ssh_policy(qr_only, key_qr, key_password))
                return
            if name == "ssh_user_policy":
                username = (data.get("user") or "").strip()
                inherit = data.get("inherit") == "on"
                qr_only = data.get("qr_only") == "on"
                key_qr = data.get("key_qr") == "on"
                key_password = data.get("key_password") == "on"
                blocked = data.get("blocked") == "on"
                if username not in interactive_accounts():
                    return self.html(400, "Not valid", flash_html("Choose an interactive account on this computer."), s)
                if username not in ssh_qr_group_members():
                    if inherit or qr_only or key_qr or key_password:
                        return self.html(400, "Not valid", flash_html("Accounts outside thessley-ssh can only be blocked or unblocked here."), s)
                    self.start_change(s, f"changing SSH access for {username}",
                                      app.change_ssh_user_blocked(username, blocked))
                    return
                if not inherit and not blocked and not (qr_only or key_qr or key_password):
                    return self.html(400, "Not valid", flash_html("Select an SSH login path, Use the computer-wide policy, or Block SSH."), s)
                if blocked and (qr_only or key_qr or key_password):
                    return self.html(400, "Not valid", flash_html("Block SSH cannot be combined with login paths."), s)
                self.start_change(s, f"changing SSH access for {username}",
                                  app.change_ssh_user_policy(username, inherit, qr_only, key_qr, key_password, blocked))
                return
            if name == "grace":
                try:
                    hours = float(value)
                except ValueError:
                    hours = -1
                if not 0 <= hours <= grants.MAX_HOURS:
                    return self.html(400, "Not valid", flash_html(f"Give a number of hours from 0 to {grants.MAX_HOURS:g}."), s)
            elif name == "session":
                try:
                    minutes = float(value)
                except ValueError:
                    minutes = -1
                if not 1 <= minutes <= 240:
                    return self.html(400, "Not valid", flash_html("Give a number of minutes from 1 to 240."), s)
            elif name == "ssh_policy_failure":
                if value not in ("fallback", "closed"):
                    return self.html(400, "Not valid", flash_html("Choose a recovery behavior."), s)
            elif name == "web_limits":
                try:
                    connections, buckets = int(data.get("connections", "")), int(data.get("buckets", ""))
                except ValueError:
                    connections, buckets = 0, 0
                if not 4 <= connections <= 256 or not 64 <= buckets <= 100000:
                    return self.html(400, "Not valid", flash_html("Connections: 4–256. IP buckets: 64–100,000."), s)
                value = f"{connections},{buckets}"
            elif name == "ssh_login_mode":
                if value not in grants.SSH_LOGIN_MODES:
                    return self.html(400, "Not valid", flash_html("Choose a supported SSH login policy."), s)
            elif name == "ssh_source_policy":
                modes = []
                if data.get("all_ips") == "on":
                    modes = ["any"]
                    if any(data.get(option) == "on" for option in ("local", "vpn", "custom")):
                        return self.html(400, "Not valid", flash_html("All IPs cannot be combined with restricted source types."), s)
                else:
                    modes = [option for option in ("local", "vpn", "custom") if data.get(option) == "on"]
                if not modes:
                    return self.html(400, "Not valid", flash_html("Choose All IPs or at least one restricted source type."), s)
                if "custom" in modes:
                    try:
                        allowed = grants.parse_ssh_allowed_ips(data.get("addresses") or "")
                    except ValueError as exc:
                        return self.html(400, "Not valid", flash_html(str(exc)), s)
                    if not allowed:
                        return self.html(400, "Not valid", flash_html("Enter at least one IP address or CIDR range for the chosen-list option."), s)
                    data["addresses"] = ", ".join(allowed)
                value = ",".join(modes)
            elif name in ("require", "self_enroll", "show_link", "localhost_only"):
                if value not in ("on", "off"):
                    return self.html(400, "Not valid", flash_html("Choose on or off."), s)
            else:
                return self.html(404, "Not found", flash_html("No such setting."), s)
            self.start_change(s, f"changing a setting ({name})", app.change_setting(name, value, data.get("addresses") or ""))

        @staticmethod
        def failure_text(f: Flow) -> str:
            """Why an enrolment ended without a new device, in words that say which of the cases it was."""
            text = "\n".join(f.lines)
            if "Timed out" in text:
                return f"No device answered in {WEB_ENROLL_WAIT // 60} minutes, so nothing was added. Start again and scan the code in time."
            if "Cancelled" in text:
                return "This was cancelled, so nothing was added."
            if "Not added." in text:
                return "The codes were not confirmed in time or did not match, so nothing was added."
            if "error:" in text:
                return "Something went wrong on this computer, so nothing was added. Check the device list before trying again."
            return "The new device was not added."

        def status(self, fid: str, s: Session | None, include_qr: bool = False) -> None:
            f = self.flow_for(fid, s)
            if f is None:
                return self.json({"state": "gone", "message": "This request is no longer here. Start again.", "bad": True})
            extra = None
            out = {"state": f.state, "link": f.link, "code": f.code, "message": "", "bad": False}
            if include_qr and f.link:
                with f.lock:
                    if not f.qr_svg_data:
                        f.qr_svg_data = base64.b64encode(qr_svg(f.link)).decode("ascii")
                    out["qr_svg"] = f.qr_svg_data
            if f.kind == "login" and f.state == "approved":
                session = app.new_session(f.user)
                f.state = "done"
                out.update(state="done", next="/keys")
                extra = [self.cookie("thessley_session", session.token), self.cookie("thessley_wait", "", 0)]
            elif f.kind == "change" and f.state == "approved":
                url, flash = app.finish(f)
                if s is not None:
                    s.flash = flash
                out.update(next=url or "/keys")
            elif f.kind == "enroll" and f.state == "confirm":
                out["csrf"] = s.csrf if s else ""
            elif f.state == "refused":
                out.update(message="It was refused or denied. Nothing was changed.", bad=True)
            elif f.state == "timeout":
                out.update(message="No answer in time. Nothing was changed.", bad=True)
            elif f.state == "failed":
                out.update(message=self.failure_text(f), bad=True)
            elif f.state == "done" and f.kind == "enroll":
                if s is not None:
                    s.flash = f"Added {f.label or 'the new device'}."
                out.update(next="/keys" if s is None or f.user == s.user else f"/keys?user={f.user}")
            self.json(out, extra)

    return Handler


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, *args, **kwargs):
        self._worker_lock = threading.Lock()
        self._active_workers = 0
        super().__init__(*args, **kwargs)

    def get_request(self):
        request, address = super().get_request()
        request.settimeout(10)
        return request, address

    def process_request(self, request, client_address):
        with self._worker_lock:
            if self._active_workers >= grants.web_settings()["max_connections"]:
                # Do not perform a TLS handshake in the accept loop for rejected work.
                self.shutdown_request(request)
                return
            self._active_workers += 1
        try:
            super().process_request(request, client_address)
        except Exception:
            with self._worker_lock:
                self._active_workers -= 1
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._worker_lock:
                self._active_workers -= 1

    def handle_error(self, request, client_address):  # a browser that hangs up mid-request is not an error here
        pass


def make_server(app: WebApp, ip: str, port: int, cert: str, key: str) -> Server:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    httpd = Server((ip, port), make_handler(app))
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True, do_handshake_on_connect=False)
    return httpd


def serve() -> int:
    app = WebApp()
    while True:
        st = grants.web_settings()
        if not st["enabled"]:
            print("The admin web page is switched off (sudo thessley-pam web on).")
            return 0
        ip = "127.0.0.1" if st["localhost_only"] else (st["listen"] or machine.lan_ip())
        cert, key = (st["cert"], st["key"]) if st["cert"] and st["key"] else default_cert_paths()
        fingerprint = ensure_cert(cert, key, [ip, "127.0.0.1"])
        httpd = make_server(app, ip, st["port"], cert, key)
        app.httpd = httpd
        app.rebind_requested = False
        print(f"Thessley admin page: https://{ip}:{st['port']}/   certificate SHA-256 {fingerprint}", flush=True)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            app.httpd = None
            httpd.server_close()
        if not app.rebind_requested:
            break
    return 0
