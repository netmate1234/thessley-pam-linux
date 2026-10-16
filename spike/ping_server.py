#!/usr/bin/env python3
"""Step 1 connectivity test: can the phone reach this PC over HTTPS with a pinned certificate?

Makes a throwaway self-signed certificate, serves one endpoint over HTTPS and prints a QR code:

    thessleypam://ping?h=<lan ip>&p=<port>&fp=<sha256 of cert DER, hex>&n=<nonce>

The app scans it, calls GET https://<h>:<p>/thessley-pam/v1/ping?n=<nonce> trusting only the
certificate whose SHA-256 is <fp>, and shows the reply. Nothing is stored; the key lives in memory
and a temp dir that is removed on exit.
"""

import argparse
import datetime
import hashlib
import ipaddress
import json
import os
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def lan_ip() -> str:
    """The address this PC uses to reach the default gateway (no packet is sent)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("192.0.2.1", 9))  # TEST-NET-1, never routed
        return s.getsockname()[0]


def make_cert(ip: str, tmp: str) -> tuple[str, str, str]:
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
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(ip))]), critical=False)
        .sign(key, hashes.SHA256())
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    cert_path = os.path.join(tmp, "cert.pem")
    key_path = os.path.join(tmp, "key.pem")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    return cert_path, key_path, hashlib.sha256(der).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=47810)
    ap.add_argument("--ip", default=None, help="address to put in the QR (default: LAN address)")
    ap.add_argument("--timeout", type=int, default=180, help="seconds before giving up")
    ap.add_argument("--wrong-fp", action="store_true",
                    help="negative test: put a fingerprint in the QR that does NOT match the served certificate; "
                         "the app must refuse to connect")
    args = ap.parse_args()

    ip = args.ip or lan_ip()
    nonce = secrets.token_urlsafe(16)
    done = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            u = urlparse(self.path)
            if u.path != "/thessley-pam/v1/ping":
                self.send_error(404)
                return
            n = parse_qs(u.query).get("n", [""])[0]
            ok = secrets.compare_digest(n, nonce)
            body = json.dumps({"ok": ok, "host": socket.gethostname(),
                               "error": "" if ok else "nonce mismatch"}).encode()
            self.send_response(200 if ok else 400)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            print(f"\n{'OK' if ok else 'REJECTED'}: ping from {self.client_address[0]}", flush=True)
            if ok:
                done.set()

        def log_message(self, fmt, *a):
            pass

    with tempfile.TemporaryDirectory(prefix="thessley-pam-") as tmp:
        cert_path, key_path, fp = make_cert(ip, tmp)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cert_path, key_path)

        httpd = ThreadingHTTPServer(("0.0.0.0", args.port), Handler)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()

        qr_fp = hashlib.sha256(b"not the served certificate").hexdigest() if args.wrong_fp else fp
        link = "thessleypam://ping?" + urlencode({"h": ip, "p": args.port, "fp": qr_fp, "n": nonce})
        subprocess.run(["qrencode", "-t", "ANSIUTF8", "-m", "2", link], check=True)
        print(link)
        print(f"Listening on https://{ip}:{args.port}  cert sha256 {fp}")
        if args.wrong_fp:
            print(f"NEGATIVE TEST: QR carries {qr_fp}; the app must refuse.")
        print(f"Scan with the app within {args.timeout}s ...", flush=True)

        ok = done.wait(args.timeout)
        httpd.shutdown()
    if args.wrong_fp:
        print("FAIL: the app connected despite a wrong fingerprint." if ok
              else "Done: no request got through (expected; check the app shows a certificate error).")
        return 1 if ok else 0
    print("PASS: phone reached this PC over pinned HTTPS." if ok else "TIMEOUT: no valid ping.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
