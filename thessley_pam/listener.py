"""HTTPS routing for one-time device approvals.

Normal approvals register temporary routes with the permanent, certificate-pinned service. Explicit non-default ports
still use the short-lived listener below for local diagnostics and isolated development runs.
"""

import contextlib
import base64
import datetime
import errno
import hashlib
import ipaddress
import json
import os
import socket
import ssl
import tempfile
import threading
from types import SimpleNamespace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

MAX_BODY = 64 * 1024
SHARED_PORT = 47810
SHARED_SOCKET = "/run/thessley-pam/approvals.sock"
MAX_FRAME = 256 * 1024

# (path, parsed JSON body) -> (HTTP status, JSON reply). Raise nothing; return an error reply instead.
Route = Callable[[str, dict], tuple[int, dict]]
RawRouteHandler = Callable[[str, dict, bytes, dict[str, str]], tuple[int, dict]]


class RawBodyRoute:
    """Opt-in route handler that receives the exact request bytes and auth headers."""

    def __init__(self, handler: RawRouteHandler, response_wait: int = 15):
        if isinstance(response_wait, bool) or not isinstance(response_wait, int) or not 1 <= response_wait <= 125:
            raise ValueError("Raw route response wait must be between 1 and 125 seconds.")
        self.handler = handler
        self.response_wait = response_wait


_MACHINE_AUTH_HEADER_NAMES = (
    "x-thessley-machine-id",
    "x-thessley-timestamp",
    "x-thessley-nonce",
    "x-thessley-signature",
)


def _machine_auth_headers(headers) -> dict[str, str]:
    selected = {}
    for name in _MACHINE_AUTH_HEADER_NAMES:
        values = headers.get_all(name, [])
        if len(values) > 1 or (values and len(values[0]) > 256):
            raise ValueError("Invalid machine authentication headers.")
        if values:
            selected[name] = values[0]
    return selected


def _dispatch_route(route, client_ip: str, body: dict, raw_body: bytes,
                    auth_headers: dict[str, str]) -> tuple[int, dict]:
    if isinstance(route, RawBodyRoute):
        return route.handler(client_ip, body, raw_body, auth_headers)
    return route(client_ip, body)


def _make_cert(ip: str, tmp: str) -> tuple[str, str, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, socket.gethostname())])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(ip))]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path = os.path.join(tmp, "cert.pem")
    key_path = os.path.join(tmp, "key.pem")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    return cert_path, key_path, hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


@contextlib.contextmanager
def listening(ip: str, routes: dict[str, Route | RawBodyRoute], first_port: int, tries: int = 10):
    """Register routes with the permanent listener; non-default ports remain available for local diagnostics."""
    if first_port == SHARED_PORT and tries == 10:
        registration = SharedRegistration(routes)
        registration.open()
        try:
            yield SimpleNamespace(port=registration.port, fingerprint=registration.fingerprint)
        finally:
            registration.close()
        return

    # Explicit non-default ports are kept for diagnostics and isolated development runs. Normal PAM and enrolment
    # traffic always uses the shared service above.
    lst = None
    for port in range(first_port, first_port + tries):
        candidate = Listener(ip, port, routes)
        try:
            candidate.__enter__()
        except OSError as e:
            if e.errno != errno.EADDRINUSE:
                raise
            continue
        lst = candidate
        break
    if lst is None:
        raise OSError(errno.EADDRINUSE, os.strerror(errno.EADDRINUSE))
    try:
        yield lst
    finally:
        lst.__exit__(None, None, None)


class SharedRegistration:
    """A private Unix-socket channel to the shared HTTPS listener for one approval flow."""

    def __init__(self, routes: dict[str, Route | RawBodyRoute]):
        self.routes = routes
        self.conn = None
        self.reader = None
        self.port = SHARED_PORT
        self.fingerprint = ""
        self.closed = threading.Event()
        self.send_lock = threading.Lock()
        self.reader_thread = None

    def open(self) -> None:
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            conn.connect(SHARED_SOCKET)
            conn.settimeout(10)
            self.conn = conn
            self.reader = conn.makefile("rb", buffering=0)
            waits = {path: route.response_wait for path, route in self.routes.items()
                     if isinstance(route, RawBodyRoute) and route.response_wait != 15}
            payload = json.dumps(
                {"op": "register", "paths": list(self.routes), "waits": waits}, separators=(",", ":")
            ).encode() + b"\n"
            conn.sendall(payload)
            raw = self.reader.readline(MAX_FRAME + 1)
            if len(raw) > MAX_FRAME or not raw.endswith(b"\n"):
                raise OSError("The approval service sent an invalid registration reply.")
            reply = json.loads(raw)
            if not reply.get("ok"):
                raise OSError(reply.get("message") or "The approval service refused this request.")
            self.port = int(reply["port"])
            self.fingerprint = str(reply["fingerprint"])
            conn.settimeout(None)
            self.reader_thread = threading.Thread(target=self._read_requests, daemon=True)
            self.reader_thread.start()
        except Exception:
            self.close()
            raise

    def _send(self, item: dict) -> None:
        raw = json.dumps(item, separators=(",", ":")).encode("utf-8") + b"\n"
        if len(raw) > MAX_FRAME:
            raise ValueError("Approval reply is too large.")
        with self.send_lock:
            if self.conn is None or self.closed.is_set():
                raise OSError("The approval service connection is closed.")
            self.conn.sendall(raw)

    def _handle_request(self, item: dict) -> None:
        request_id = str(item.get("id", ""))
        try:
            path = str(item["path"])
            route = self.routes.get(path)
            if route is None:
                status, body = 404, {"result": "error", "message": "Not found."}
            else:
                client_ip = str(item.get("client_ip", ""))
                payload = item.get("body")
                if not isinstance(payload, dict):
                    status, body = 400, {"result": "error", "message": "Body is not a JSON object."}
                else:
                    try:
                        raw_body = base64.b64decode(item.get("raw_body_b64", ""), validate=True)
                        auth_headers = item.get("auth_headers", {})
                        if len(raw_body) > MAX_BODY or not isinstance(auth_headers, dict):
                            raise ValueError
                        if any(not isinstance(k, str) or not isinstance(v, str) for k, v in auth_headers.items()):
                            raise ValueError
                        status, body = _dispatch_route(route, client_ip, payload, raw_body, auth_headers)
                    except (ValueError, TypeError):
                        status, body = 400, {"result": "error", "message": "Invalid forwarded request metadata."}
            self._send({"type": "response", "id": request_id, "status": int(status), "body": body})
        except Exception:
            try:
                self._send({"type": "response", "id": request_id, "status": 500,
                            "body": {"result": "error", "message": "Could not process this response."}})
            except OSError:
                pass

    def _read_requests(self) -> None:
        reader = self.reader
        try:
            while not self.closed.is_set():
                raw = reader.readline(MAX_FRAME + 1)
                if not raw:
                    break
                if len(raw) > MAX_FRAME or not raw.endswith(b"\n"):
                    break
                item = json.loads(raw)
                if item.get("type") != "request":
                    continue
                threading.Thread(target=self._handle_request, args=(item,), daemon=True).start()
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            pass
        finally:
            self.closed.set()

    def close(self) -> None:
        if self.closed.is_set() and self.conn is None:
            return
        self.closed.set()
        conn, self.conn = self.conn, None
        reader, self.reader = self.reader, None
        if conn is not None:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            conn.close()
        if reader is not None:
            try:
                reader.close()
            except OSError:
                pass
        if self.reader_thread is not None and self.reader_thread is not threading.current_thread():
            self.reader_thread.join(timeout=1)


class Listener:
    """POST-only JSON server for the routes given. Use as a context manager."""

    def __init__(self, ip: str, port: int, routes: dict[str, Route | RawBodyRoute]):
        self.ip, self.port, self.routes = ip, port, routes
        self.fingerprint = ""
        self._tmp = None
        self._httpd = None

    def __enter__(self) -> "Listener":
        self._tmp = tempfile.TemporaryDirectory(prefix="thessley-pam-")
        cert_path, key_path, self.fingerprint = _make_cert(self.ip, self._tmp.name)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cert_path, key_path)
        # The key is loaded; nothing needs it on disk any more.
        self._tmp.cleanup()

        routes = self.routes

        class Handler(BaseHTTPRequestHandler):
            def _reply(self, status: int, body: dict) -> None:
                raw = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self):
                route = routes.get(self.path)
                if route is None:
                    self._reply(404, {"result": "error", "message": "Not found."})
                    return
                length = int(self.headers.get("Content-Length") or 0)
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
                    auth_headers = _machine_auth_headers(self.headers)
                except ValueError:
                    self._reply(400, {"result": "error", "message": "Body is not a JSON object."})
                    return
                status, reply = _dispatch_route(route, self.client_address[0], body, raw_body, auth_headers)
                self._reply(status, reply)

            def log_message(self, fmt, *a):
                pass

        class Server(ThreadingHTTPServer):
            daemon_threads = True

            def handle_error(self, request, client_address):
                pass  # a phone that hangs up mid-request (e.g. after a certificate mismatch) is not an error here

        self._httpd = Server((self.ip, self.port), Handler)
        self._httpd.socket = ctx.wrap_socket(self._httpd.socket, server_side=True)
        threading.Thread(target=self._httpd.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc) -> None:
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
