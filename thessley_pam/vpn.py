"""OpenVPN second step: a client certificate gets the tunnel only after the account's device approves.

Two programs, split so that OpenVPN itself never runs as root and never reads the keys:

  thessley-pam vpn serve   (root, systemd)  the approval daemon. Listens on a unix socket for "approve this account", runs the
                           usual device approval (pam.run: link, QR, signed answer, 90 s+ window, passes) and serves a small
                           public HTTPS page that shows the QR code to the person at the VPN client.
  thessley-pam vpn auth    (as OpenVPN's user) OpenVPN's auth-user-pass-verify script. It asks the daemon, tells the client to
                           open the page (OpenVPN 2.6 "pending authentication", method openurl), and exits 2 = "deferred"; a
                           background child then writes 1 or 0 into OpenVPN's auth_control_file when the device has answered.

The certificate is the first factor: OpenVPN checks it in the TLS handshake before it runs the script, so a stranger cannot make
anybody's phone ask. The script also insists that the certificate's common name IS the account name.
"""

import base64
import contextlib
import html
import json
import os
import re
import secrets
import socket
import socketserver
import ssl
import sys
import threading
import time
import types
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import grants, machine, pam, store

SOCKET = "/run/thessley-pam/vpn.sock"
SERVICE = "openvpn"
USER_RE = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}$")
RHOST_RE = re.compile(r"^[0-9A-Fa-f:.]{1,45}$")
FLOW_ID = re.compile(r"^[0-9a-f]{32}$")
DEVICE_PART = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")
MAX_FLOWS = 20
KEEP_SECONDS = 15 * 60
READY_WAIT = 15  # seconds for the approval to produce its link

REASONS = {
    "refused": "The approval was denied on the device.",
    "timeout": "Nobody approved in time.",
    "starting": "The approval could not start.",
    "busy": "Another approval is using the approval port. Try again in a minute.",
}


class Flow:
    """One VPN login waiting for its device."""

    def __init__(self, user: str, rhost: str):
        self.id = secrets.token_hex(16)  # in the page address: whoever has it may look at the QR code, which approves nothing
        self.user, self.rhost = user, rhost
        self.link = ""
        self.lines: list[str] = []
        self.state = "starting"  # starting, waiting, approved, refused, timeout
        self.ready = threading.Event()     # the link is known, or the flow has ended
        self.finished = threading.Event()
        self.created = time.time()

    def say(self, text) -> None:
        for line in str(text).splitlines():
            self.lines.append(line)
            m = re.match(r"Link: (thessleypam://\S+)", line)
            if m:
                self.link = m.group(1)
                self.state = "waiting"
                self.ready.set()


MAX_BODY = 64 * 1024


class Approvals:
    """The flows in progress. `runner` is pam.run; tests give a stand-in.

    The device's answers do not come to a listener of their own, one per approval, on a port that may be taken (the one forwarded
    port was shared with every other approval on the computer). They come to the permanent HTTPS server of the QR page, at
    /thessley-pam/v1/vpn/<request id>/respond; the link carries that server's port and certificate fingerprint. Any number of
    approvals can be open at once, and nothing opens or closes a port per approval."""

    def __init__(self, settings=grants.vpn_settings, runner=pam.run):
        self.settings, self.runner = settings, runner
        self.flows: dict[str, Flow] = {}
        self.lock = threading.Lock()
        self.routes: dict[str, object] = {}     # path -> (client address, body) -> (status, reply)
        self.page_fingerprint = ""              # the page server's certificate, set when it starts

    @contextlib.contextmanager
    def listening(self, ip: str, routes: dict):
        """What pam.run uses instead of a listener of its own: register the routes on the page server for as long as the approval
        is open. The link gets the page server's public port and certificate."""
        with self.lock:
            self.routes.update(routes)
        try:
            yield types.SimpleNamespace(port=self.settings()["page_port"], fingerprint=self.page_fingerprint)
        finally:
            with self.lock:
                for path in routes:
                    self.routes.pop(path, None)

    def route(self, path: str):
        with self.lock:
            return self.routes.get(path)

    def sweep(self) -> None:
        now = time.time()
        with self.lock:
            for fid in [k for k, f in self.flows.items() if now - f.created > KEEP_SECONDS and f.finished.is_set()]:
                del self.flows[fid]

    def start(self, user: str, rhost: str) -> Flow | str:
        """A flow, or the reason there is none."""
        if not USER_RE.match(user or ""):
            return "That is not an account name."
        if rhost and not RHOST_RE.match(rhost):
            rhost = ""
        try:
            devices = store.active_devices(user)
        except KeyError:
            return "No such account."
        if not devices:
            return "This account has no device that may approve."
        self.sweep()
        with self.lock:
            # A client that retries (OpenVPN Connect does, every few seconds) must join the approval already waiting for this
            # account from this address instead of opening a second one: there is one approval port, and the person has one
            # page and one QR code to answer.
            for waiting in self.flows.values():
                if waiting.user == user and waiting.rhost == rhost and not waiting.finished.is_set():
                    return waiting
        flow = Flow(user, rhost)
        with self.lock:
            if sum(1 for f in self.flows.values() if not f.finished.is_set()) >= MAX_FLOWS:
                return "Too many approvals are waiting."
            self.flows[flow.id] = flow
        threading.Thread(target=self._work, args=(flow,), daemon=True).start()
        return flow

    def _work(self, flow: Flow) -> None:
        st = self.settings()
        env = {"PAM_TYPE": "auth", "PAM_USER": flow.user, "PAM_SERVICE": SERVICE, "PAM_RHOST": flow.rhost, "PAM_TTY": "vpn",
               "PAM_PUBLIC_HOST": st["public_host"], "PAM_ALWAYS_LINK": "1"}
        try:
            rc = self.runner(env, say=flow.say, wait=st["wait"], req_type="vpn", listening=self.listening)
        except Exception as exc:  # strict: any trouble is a refusal
            flow.say(f"error: {exc!r}")
            rc = pam.REFUSED
        text = "\n".join(flow.lines)
        if rc == pam.OK:
            flow.state = "approved"
        elif "no answer" in text:
            flow.state = "timeout"
        elif "could not start" in text:   # the listener could not open: its port is taken by another approval
            flow.state = "busy"
        else:
            flow.state = "refused"
        flow.finished.set()
        flow.ready.set()

    def get(self, fid: str) -> Flow | None:
        if not FLOW_ID.match(fid or ""):
            return None
        with self.lock:
            return self.flows.get(fid)


def page_url(flow: Flow, settings: dict) -> str:
    host = settings["public_host"] or machine.lan_ip()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"  # an IPv6 address
    return f"https://{host}:{settings['page_port']}/vpn/{flow.id}"


# ---- the daemon ----------------------------------------------------------------------------------------------------

def make_socket_server(approvals: Approvals, path: str = SOCKET, group: str = "") -> socketserver.ThreadingUnixStreamServer:
    class Handler(socketserver.StreamRequestHandler):
        def send(self, obj: dict) -> None:
            try:
                self.wfile.write((json.dumps(obj) + "\n").encode())
                self.wfile.flush()
            except OSError:
                pass  # the client (OpenVPN's script) is gone; the approval itself carries on or expires

        def handle(self) -> None:
            try:
                req = json.loads(self.rfile.readline(4096) or b"{}")
                user, rhost = str(req.get("user", "")), str(req.get("rhost", ""))
            except (ValueError, AttributeError):
                return self.send({"done": True, "ok": False, "reason": "Bad request."})
            st = approvals.settings()
            flow = approvals.start(user, rhost)
            if isinstance(flow, str):
                return self.send({"done": True, "ok": False, "reason": flow})
            flow.ready.wait(READY_WAIT)
            if not flow.finished.is_set():
                if not flow.link:
                    return self.send({"done": True, "ok": False, "reason": REASONS["starting"]})
                self.send({"url": page_url(flow, st), "timeout": int(st["wait"])})
                flow.finished.wait(st["wait"] + 20)
            ok = flow.state == "approved"
            self.send({"done": True, "ok": ok, "reason": "" if ok else REASONS.get(flow.state, REASONS["refused"])})

    if os.path.exists(path):
        os.unlink(path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    server = socketserver.ThreadingUnixStreamServer(path, Handler)
    server.daemon_threads = True
    os.chmod(path, 0o660)
    if group:
        try:
            import grp
            os.chown(path, 0, grp.getgrnam(group).gr_gid)
        except (KeyError, PermissionError):
            os.chmod(path, 0o600)  # no such group: only root; the script will say it cannot connect
    return server


# ---- the public QR page --------------------------------------------------------------------------------------------

PAGE_CSS = ("body{font-family:system-ui,sans-serif;margin:0;padding:24px 16px;background:#f6f7f9;color:#14181f}"
            "main{max-width:42rem;margin:0 auto}h1{font-size:1.2rem}.card{background:#fff;border-radius:12px;padding:20px;"
            "box-shadow:0 1px 3px #0002}.qr{width:100%;max-width:36rem;display:block;margin:12px auto;background:#fff;padding:12px;border-radius:8px;box-sizing:border-box}"
            ".mono{font-family:ui-monospace,monospace;font-size:.75rem;word-break:break-all}.dim{color:#5a6472}"
            ".btn{display:inline-block;padding:10px 16px;border-radius:8px;background:#1b5fd6;color:#fff;text-decoration:none}"
            ".ok{color:#0a7a3b}.bad{color:#b3261e}"
            "@media(prefers-color-scheme:dark){body{background:#14161a;color:#e8ebf0}.card{background:#1d2128}.dim{color:#9aa4b2}}")


def render_page(flow: Flow, nonce: str = "") -> str:
    esc = html.escape
    # While waiting, a small script asks for the state every 2 s and reloads only when it changes (the link appeared, or the
    # answer came). A page that reloads itself every few seconds makes the QR code flicker, which cannot be scanned.
    poll = ""
    if not flow.finished.is_set() and nonce:
        poll = (f'<script nonce="{esc(nonce, quote=True)}">(function(){{var had={"true" if flow.link else "false"};'
                f'function tick(){{fetch("/vpn/{flow.id}.json",{{cache:"no-store"}}).then(function(r){{return r.json()}})'
                '.then(function(s){if(s.finished||s.has_link!==had){location.reload();return}setTimeout(tick,2000)})'
                '.catch(function(){setTimeout(tick,4000)})}tick()})();</script>')
    if flow.state == "approved":
        body = '<p class="ok"><strong>Approved.</strong> The VPN is connecting. You can close this page.</p>'
    elif flow.finished.is_set():
        body = f'<p class="bad"><strong>Not approved.</strong> {esc(REASONS.get(flow.state, REASONS["refused"]))}</p>'
    elif flow.link:
        body = ('<p>Scan this code with the Thessley Passkey app on your phone, then approve.</p>'
                f'<img class="qr" alt="QR code" src="/vpn/{flow.id}.svg">'
                f'<p><a class="btn" href="{esc(flow.link, quote=True)}">Open in the Thessley app</a></p>'
                f'<p class="dim">Or paste this link into the app:</p><p class="mono">{esc(flow.link)}</p>')
    else:
        body = '<p class="dim">Getting the request ready…</p>'
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>VPN login for {esc(flow.user)} · Thessley Passkeys for {esc(machine.hostname())}</title>'
            f'<style>{PAGE_CSS}</style></head><body><main><h1>VPN login for {esc(flow.user)}</h1>'
            f'<div class="card">{body}</div>{poll}</main></body></html>')


def make_page_handler(approvals: Approvals, qr_svg):
    class Handler(BaseHTTPRequestHandler):
        server_version = "thessley-vpn"
        sys_version = ""

        def log_message(self, *args) -> None:  # noqa: D401 - quiet; the approvals are logged by pam.run
            pass

        def reply(self, code: int, body: bytes, ctype: str, nonce: str = "") -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            script = f"script-src 'nonce-{nonce}'; connect-src 'self'; " if nonce else ""
            self.send_header("Content-Security-Policy",
                             f"default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; {script}base-uri 'none'; form-action 'none'")
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:  # noqa: N802
            """The device's answer to a VPN approval: only the routes of approvals that are open right now exist."""
            route = approvals.route(self.path.split("?")[0])
            if route is None:
                return self.json(404, {"result": "error", "message": "Not found."})
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0
            if length <= 0 or length > MAX_BODY:
                return self.json(400, {"result": "error", "message": "Bad request body."})
            try:
                body = json.loads(self.rfile.read(length))
                if not isinstance(body, dict):
                    raise ValueError
            except ValueError:
                return self.json(400, {"result": "error", "message": "Body is not a JSON object."})
            status, reply = route(self.client_address[0], body)
            self.json(status, reply)

        def json(self, status: int, obj: dict) -> None:
            self.reply(status, json.dumps(obj).encode(), "application/json")

        def do_GET(self) -> None:  # noqa: N802
            m = re.fullmatch(r"/vpn/([0-9a-f]{32})(\.svg|\.json)?", self.path.split("?")[0])
            flow = approvals.get(m.group(1)) if m else None
            if flow is None:
                return self.reply(404, b"Not found", "text/plain; charset=utf-8")
            if m.group(2) == ".svg":
                if not flow.link:
                    return self.reply(404, b"Not found", "text/plain; charset=utf-8")
                return self.reply(200, qr_svg(flow.link), "image/svg+xml")
            if m.group(2) == ".json":
                state = {"finished": flow.finished.is_set(), "has_link": bool(flow.link)}
                return self.reply(200, json.dumps(state).encode(), "application/json")
            nonce = secrets.token_urlsafe(12)
            self.reply(200, render_page(flow, nonce).encode(), "text/html; charset=utf-8", nonce)

    return Handler


class _VPNPageServer(ThreadingHTTPServer):
    """Keep slow TLS handshakes out of the accept loop so one stalled client cannot block the QR page."""

    daemon_threads = True
    request_queue_size = 32

    def __init__(self, address, handler, context: ssl.SSLContext):
        self.tls_context = context
        super().__init__(address, handler)

    def get_request(self):
        request, client_address = super().get_request()
        request.settimeout(10)
        request = self.tls_context.wrap_socket(request, server_side=True, do_handshake_on_connect=False)
        request.settimeout(10)
        return request, client_address


def make_page_server(approvals: Approvals, ip: str, port: int, cert: str, key: str, qr_svg) -> ThreadingHTTPServer:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    return _VPNPageServer((ip, port), make_page_handler(approvals, qr_svg), ctx)


def serve() -> int:
    from . import web
    st = grants.vpn_settings()
    if not st["enabled"]:
        print("The VPN approval is switched off (sudo thessley-pam vpn on).")
        return 0
    ip = machine.lan_ip()
    cert = os.path.join(store.BASE, "vpn", "cert.pem")
    key = os.path.join(store.BASE, "vpn", "key.pem")
    names = [ip, "127.0.0.1"] + ([st["public_host"]] if st["public_host"] else [])
    fingerprint = web.ensure_cert(cert, key, names)
    approvals = Approvals()
    approvals.page_fingerprint = fingerprint        # the links carry this: the device's answers come to this server
    page = make_page_server(approvals, ip, st["page_port"], cert, key, web.qr_svg)
    threading.Thread(target=page.serve_forever, daemon=True).start()
    sock = make_socket_server(approvals, SOCKET, st["socket_group"])
    print(f"Thessley VPN approval: page https://{ip}:{st['page_port']}/ (certificate SHA-256 {fingerprint}), socket {SOCKET}", flush=True)
    try:
        sock.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


# ---- OpenVPN's script ----------------------------------------------------------------------------------------------

def _write(path: str, text: str) -> None:
    with open(path, "w") as f:
        f.write(text)


def _log_default(text: str) -> None:
    print(text, file=sys.stderr)
    try:
        import syslog
        syslog.openlog("thessley-pam-vpn", syslog.LOG_PID, syslog.LOG_AUTHPRIV)
        syslog.syslog(syslog.LOG_INFO, text)   # in the journal: journalctl -t thessley-pam-vpn
    except Exception:  # noqa: BLE001 - logging must never break a login
        pass


def pending_method(env, url: str) -> tuple[str, str] | None:
    """How to tell this client to open the approval page, from the ways it says it can (IV_SSO, which OpenVPN gives the script):
    "openurl" (OpenVPN for Android, the 2.6 command line client when set: OpenVPN adds OPEN_URL: itself) or "webauth" (OpenVPN
    Connect). For webauth OpenVPN sends the text as it is, so it is the whole message: WEB_AUTH:<flags>:<url>, flag `external` =
    the system browser, where the page's "Open in the Thessley app" button can start the app. A client that lists neither cannot
    show a page."""
    offered = {m.strip().lower() for m in env.get("IV_SSO", "").split(",") if m.strip()}
    if not offered or "openurl" in offered:      # nothing known: the OpenVPN default
        return "openurl", url
    if "webauth" in offered:
        return "webauth", "WEB_AUTH:external:" + url
    return None


def certificate_belongs_to(cn: str, user: str) -> bool:
    """The certificate's name is the account, or `account@device`: one certificate per device, so that two devices of one account do
    not drop each other's connection (OpenVPN allows one connection per certificate name). An account cannot contain '@', so the
    account part is unambiguous."""
    if cn == user:
        return True
    account, at, device = cn.partition("@")
    return bool(at) and account == user and bool(DEVICE_PART.match(device))


def authenticate(env, sock_path: str = SOCKET, fork=os.fork, log=_log_default) -> int:
    """auth-user-pass-verify (via-env). 0 = accept, 1 = reject, 2 = deferred (a child finishes it)."""
    user, cn, rhost = env.get("username", ""), env.get("common_name", ""), env.get("untrusted_ip", "") or env.get("untrusted_ip6", "")
    control, pending, reason_file = env.get("auth_control_file"), env.get("auth_pending_file"), env.get("auth_failed_reason_file")

    def refuse(reason: str) -> int:
        log(f"thessley-pam vpn: {reason}")
        if reason_file:
            try:
                _write(reason_file, reason)
            except OSError:
                pass
        return 1

    if not USER_RE.match(user):
        return refuse("not an account name")
    if not certificate_belongs_to(cn, user):
        return refuse(f"the certificate belongs to {cn!r}, not to {user!r}")
    if control and pending and pending_method(env, "x") is None:
        # before anything starts: an approval that nobody can see would hold the one approval port for its whole window
        log(f"approval page for {user} from {rhost}: client offers IV_SSO={env.get('IV_SSO', '')!r}, method none")
        return refuse("this VPN client cannot show a web page (it offers: " + env.get("IV_SSO", "") + ")")
    try:
        conn = socket.socket(socket.AF_UNIX)
        conn.settimeout(300)
        conn.connect(sock_path)
        f = conn.makefile("rw", encoding="utf-8")
        f.write(json.dumps({"user": user, "rhost": rhost}) + "\n")
        f.flush()

        def read() -> dict:
            line = f.readline()
            if not line:
                raise OSError("the approval daemon hung up")
            return json.loads(line)

        msg = read()
        if msg.get("done"):
            return 0 if msg.get("ok") is True else refuse(str(msg.get("reason") or "refused"))
        url, timeout = str(msg.get("url", "")), int(msg.get("timeout", 180))
        if not (control and pending and url.startswith("https://")):
            # An OpenVPN without deferred authentication: hold the connection and wait here.
            msg = read()
            return 0 if msg.get("done") and msg.get("ok") is True else refuse(str(msg.get("reason") or "refused"))
        chosen = pending_method(env, url)
        log(f"approval page for {user} from {rhost}: client {env.get('IV_GUI_VER') or env.get('IV_PLAT') or '?'} offers "
            f"IV_SSO={env.get('IV_SSO', '(not given)')!r}, method {chosen[0] if chosen else 'none'}")
        method, extra = chosen   # not None: refused above, before the approval started
        _write(pending, f"{timeout}\n{method}\n{extra}\n")
        pid = fork()
    except (OSError, ValueError) as exc:
        return refuse(f"cannot reach the approval daemon ({exc})")
    if pid:
        return 2  # OpenVPN waits for auth_control_file
    try:
        os.setsid()
        finish(read, control, reason_file)
    finally:
        os._exit(0)


def finish(read, control: str, reason_file: str | None) -> bool:
    """The deferred child: wait for the daemon's verdict and write it where OpenVPN looks (1 = accept, 0 = reject)."""
    ok, why = False, "refused"
    try:
        msg = read()
        ok = msg.get("done") is True and msg.get("ok") is True
        why = str(msg.get("reason") or "refused")
    except (OSError, ValueError):
        why = "the approval daemon hung up"
    if not ok and reason_file:
        try:
            _write(reason_file, why)
        except OSError:
            pass
    _write(control, "1" if ok else "0")
    return ok
