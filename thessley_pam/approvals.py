"""The shared HTTPS and local IPC service for SSH and other local phone approvals.

VPN approvals stay on their separate HTTPS service and port 47830.
"""

from __future__ import annotations

import base64
import json
import os
import re
import socket
import ssl
import stat
import struct
import threading
import secrets
from concurrent.futures import Future, TimeoutError
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import machine, store
from .listener import _machine_auth_headers

SOCKET = "/run/thessley-pam/approvals.sock"
PORT = 47810
MAX_BODY = 64 * 1024
MAX_FRAME = 256 * 1024
MAX_ROUTES = 2048
MAX_REGISTRATIONS = 512
RESPONSE_WAIT = 15
ROUTE_RE = re.compile(
    r"^(?:/thessley-pam/v1/[a-z0-9_-]{1,32}/[A-Za-z0-9_-]{1,64}/[a-z0-9-]{1,32}"
    r"|/thessley-ad/v1/[a-z0-9_-]{1,32}(?:/[A-Za-z0-9_-]{1,64}){0,3})$"
)


def _readline(sock: socket.socket) -> bytes:
    data = bytearray()
    while len(data) <= MAX_FRAME:
        part = sock.recv(1)
        if not part:
            break
        data.extend(part)
        if part == b"\n":
            return bytes(data)
    if data:
        raise ValueError("message too large or missing newline")
    return b""


def _send(sock: socket.socket, value: dict) -> None:
    raw = json.dumps(value, separators=(",", ":")).encode("utf-8") + b"\n"
    if len(raw) > MAX_FRAME:
        raise ValueError("message too large")
    sock.sendall(raw)


class Registration:
    """A live PAM helper and its temporary HTTP routes."""

    def __init__(self, server: "ApprovalServer", conn: socket.socket, paths: list[str]):
        self.server, self.conn, self.paths = server, conn, paths
        self.pending: dict[str, Future] = {}
        self.lock = threading.Lock()
        self.send_lock = threading.Lock()
        self.closed = threading.Event()

    def send(self, value: dict) -> None:
        with self.send_lock:
            _send(self.conn, value)

    def read_responses(self) -> None:
        try:
            while True:
                raw = _readline(self.conn)
                if not raw:
                    break
                item = json.loads(raw)
                if item.get("type") != "response":
                    continue
                with self.lock:
                    future = self.pending.pop(str(item.get("id", "")), None)
                if future is not None:
                    future.set_result((int(item["status"]), item["body"]))
        except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
            pass
        finally:
            self.close()

    def forward(self, path: str, client_ip: str, body: dict, raw_body: bytes,
                auth_headers: dict[str, str]) -> tuple[int, dict]:
        request_id = secrets.token_urlsafe(12)
        future: Future = Future()
        with self.lock:
            if self.closed.is_set():
                return 503, {"result": "error", "message": "Approval is no longer active."}
            self.pending[request_id] = future
        try:
            self.send({
                "type": "request", "id": request_id, "path": path, "client_ip": client_ip,
                "body": body, "raw_body_b64": base64.b64encode(raw_body).decode("ascii"),
                "auth_headers": auth_headers,
            })
        except (OSError, ValueError):
            with self.lock:
                self.pending.pop(request_id, None)
            self.close()
            return 503, {"result": "error", "message": "Approval is no longer active."}
        try:
            return future.result(timeout=RESPONSE_WAIT)
        except TimeoutError:
            with self.lock:
                self.pending.pop(request_id, None)
            return 504, {"result": "error", "message": "Approval handler did not respond."}

    def close(self) -> None:
        if self.closed.is_set():
            return
        self.closed.set()
        self.server.unregister(self)
        with self.lock:
            pending = list(self.pending.values())
            self.pending.clear()
        for future in pending:
            if not future.done():
                future.set_result((503, {"result": "error", "message": "Approval is no longer active."}))
        try:
            self.conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.conn.close()


class ApprovalServer:
    def __init__(self, fingerprint: str):
        self.fingerprint = fingerprint
        self.routes: dict[str, Registration] = {}
        self.lock = threading.Lock()
        self.httpd = None
        self.control = None

    def register(self, conn: socket.socket) -> None:
        registration = None
        try:
            cred = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            _pid, uid, _gid = struct.unpack("3i", cred)
            if uid != 0:
                raise PermissionError("Only root may register approval routes.")
            request = json.loads(_readline(conn))
            paths = request.get("paths")
            if request.get("op") != "register" or not isinstance(paths, list) or not 1 <= len(paths) <= 8:
                raise ValueError("Invalid route registration.")
            if any(not isinstance(path, str) or not ROUTE_RE.fullmatch(path) for path in paths):
                raise ValueError("Invalid approval route.")
            if len(set(paths)) != len(paths):
                raise ValueError("Duplicate approval route.")
            registration = Registration(self, conn, paths)
            with self.lock:
                if len(self.routes) + len(paths) > MAX_ROUTES or len({id(r) for r in self.routes.values()}) >= MAX_REGISTRATIONS:
                    raise BlockingIOError("The approval service is busy.")
                if any(path in self.routes for path in paths):
                    raise FileExistsError("An approval route is already registered.")
                for path in paths:
                    self.routes[path] = registration
            _send(conn, {"ok": True, "port": PORT, "fingerprint": self.fingerprint})
            conn.settimeout(None)
            registration.read_responses()
            return
        except Exception as exc:
            try:
                _send(conn, {"ok": False, "message": str(exc)[:256]})
            except OSError:
                pass
        finally:
            if registration is not None:
                registration.close()
            else:
                conn.close()

    def unregister(self, registration: Registration) -> None:
        with self.lock:
            for path in registration.paths:
                if self.routes.get(path) is registration:
                    del self.routes[path]

    def route(self, path: str) -> Registration | None:
        with self.lock:
            return self.routes.get(path)

    def make_http_server(self, ip: str, cert_path: str, key_path: str):
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _reply(self, status: int, body: dict) -> None:
                raw = json.dumps(body).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(raw)
                self.close_connection = True

            def do_POST(self):
                registration = owner.route(self.path)
                if registration is None:
                    self._reply(404, {"result": "error", "message": "Not found."})
                    return
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                except ValueError:
                    length = 0
                if length <= 0 or length > MAX_BODY:
                    self._reply(400, {"result": "error", "message": "Bad request body."})
                    return
                try:
                    raw_body = self.rfile.read(length)
                    if len(raw_body) != length:
                        raise ValueError
                    body = json.loads(raw_body)
                    if not isinstance(body, dict):
                        raise ValueError
                except (ValueError, json.JSONDecodeError):
                    self._reply(400, {"result": "error", "message": "Body is not a JSON object."})
                    return
                try:
                    auth_headers = _machine_auth_headers(self.headers)
                except (AttributeError, ValueError):
                    self._reply(400, {"result": "error", "message": "Invalid machine authentication headers."})
                    return
                status, reply = registration.forward(
                    self.path, self.client_address[0], body, raw_body, auth_headers
                )
                self._reply(status, reply)

            def log_message(self, fmt, *args):
                pass

        class Server(ThreadingHTTPServer):
            allow_reuse_address = True
            daemon_threads = True
            block_on_close = False

            def get_request(self):
                request, client_address = super().get_request()
                request.settimeout(10)
                request = context.wrap_socket(request, server_side=True, do_handshake_on_connect=False)
                request.settimeout(10)
                return request, client_address

            def handle_error(self, request, client_address):
                pass

        httpd = Server((ip, PORT), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cert_path, key_path)
        return httpd

    def serve(self) -> int:
        ip = machine.lan_ip()
        cert_dir = os.path.join(store.BASE, "approvals")
        cert_path, key_path = os.path.join(cert_dir, "cert.pem"), os.path.join(cert_dir, "key.pem")
        from . import web
        store.ensure_dirs()
        self.fingerprint = web.ensure_cert(cert_path, key_path, [ip])
        self.httpd = self.make_http_server(ip, cert_path, key_path)
        runtime_dir = os.path.dirname(SOCKET)
        os.makedirs(runtime_dir, mode=0o755, exist_ok=True)
        runtime_stat = os.stat(runtime_dir, follow_symlinks=False)
        if not stat.S_ISDIR(runtime_stat.st_mode) or runtime_stat.st_uid != 0 or runtime_stat.st_mode & 0o022:
            raise RuntimeError(f"Unsafe approval runtime directory: {runtime_dir}")
        try:
            existing = os.lstat(SOCKET)
        except FileNotFoundError:
            pass
        else:
            if not stat.S_ISSOCK(existing.st_mode) or existing.st_uid != 0:
                raise RuntimeError(f"Refusing to replace unsafe socket path: {SOCKET}")
            os.unlink(SOCKET)
        self.control = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.control.bind(SOCKET)
        os.chmod(SOCKET, 0o600)
        self.control.listen(128)
        threading.Thread(target=self.httpd.serve_forever, name="approval-https", daemon=True).start()
        print(f"Thessley approval service: https://{ip}:{PORT}/ (certificate SHA-256 {self.fingerprint})", flush=True)
        try:
            while True:
                conn, _ = self.control.accept()
                conn.settimeout(15)
                threading.Thread(target=self.register, args=(conn,), daemon=True).start()
        except KeyboardInterrupt:
            pass
        finally:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.control.close()
            try:
                os.unlink(SOCKET)
            except FileNotFoundError:
                pass
        return 0


def serve() -> int:
    return ApprovalServer("").serve()
