"""End-to-end enrolment against the real listener, with this test playing the phone.

Runs without root: store paths point at a temp dir and the root check, QR printing and the yes/no prompt are
stubbed. Run from the repo root:  python3 -I -m unittest discover -s tests -t .
"""

import base64
import hashlib
import http.client
import json
import os
import socket
import ssl
import sys
import tempfile
import threading
import time
import types
import unittest
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from thessley_pam import cli, protocol, store

PORT = 47899


class FakePhone:
    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.spki = base64.b64encode(self.key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()

    def sign(self, msg: bytes) -> str:
        return base64.b64encode(self.key.sign(msg, ec.ECDSA(hashes.SHA256()))).decode()

    @staticmethod
    def post(q: dict, body: dict, pin: str | None = None) -> tuple[int, dict]:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # checked by hand below, like PinnedClient
        conn = http.client.HTTPSConnection(q["h"], int(q["p"]), context=ctx, timeout=30)
        conn.connect()
        served = hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest()
        if served != (pin or q["fp"]):
            conn.close()
            raise ssl.SSLError("certificate does not match the QR code")
        conn.request("POST", f"/thessley-pam/v1/enroll/{q['id']}/respond", json.dumps(body),
                     {"Content-Type": "application/json"})
        r = conn.getresponse()
        return r.status, json.loads(r.read())

    def enroll_body(self, q: dict, ts: int | None = None, user: str | None = None) -> dict:
        ts = int(time.time()) if ts is None else ts
        msg = protocol.canonical("enroll", q["id"], q["m"], user or q["u"], q["n"], ts, "register")
        return {"public_key": self.spki, "proof_signature": self.sign(msg), "timestamp": ts,
                "label": "Test phone", "attestation_chain": []}


class EnrollTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        store.BASE = self.tmp.name
        store.USERS = os.path.join(self.tmp.name, "users")
        self.user = os.environ.get("USER") or "ubuntu"
        self.links = []
        self.answer = True
        cli._need_root = lambda: None
        cli._show_qr = self.links.append
        cli._ask_yes = lambda prompt, timeout: self.answer
        cli.machine.lan_ip = lambda: "127.0.0.1"
        cli._open_tty = lambda: open(os.devnull)
        self.result = None

    def tearDown(self):
        self.tmp.cleanup()

    def start(self):
        args = types.SimpleNamespace(user=self.user, port=PORT)
        t = threading.Thread(target=lambda: setattr(self, "result", cli.cmd_enroll(args)), daemon=True)
        t.start()
        for _ in range(50):
            if self.links:
                break
            time.sleep(0.1)
        q = {k: v[0] for k, v in parse_qs(urlparse(self.links[0]).query).items()}
        return t, q

    def test_happy_path_stores_key(self):
        t, q = self.start()
        phone = FakePhone()
        status, reply = phone.post(q, phone.enroll_body(q))
        t.join(10)
        self.assertEqual((status, reply["result"]), (200, "ok"))
        self.assertEqual(self.result, 0)
        devs = store.devices(self.user)
        self.assertEqual([d["public_key"] for d in devs], [phone.spki])
        self.assertEqual(reply["credential_id"], devs[0]["credential_id"])
        mode = os.stat(os.path.join(store.USERS, f"{self.user}.json")).st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_no_on_computer_stores_nothing(self):
        self.answer = False
        t, q = self.start()
        phone = FakePhone()
        status, reply = phone.post(q, phone.enroll_body(q))
        t.join(10)
        self.assertEqual(reply["result"], "denied")
        self.assertEqual(store.devices(self.user), [])

    def test_rejections(self):
        t, q = self.start()
        phone = FakePhone()
        # Signature over another user's name.
        self.assertEqual(phone.post(q, phone.enroll_body(q, user="root"))[0], 400)
        # Stale timestamp.
        self.assertEqual(phone.post(q, phone.enroll_body(q, ts=int(time.time()) - 600))[0], 400)
        # Someone else's key with this phone's signature.
        other = FakePhone()
        body = phone.enroll_body(q)
        body["public_key"] = other.spki
        self.assertEqual(phone.post(q, body)[0], 400)
        # Wrong certificate pin: the phone must refuse before sending.
        with self.assertRaises(ssl.SSLError):
            phone.post(q, phone.enroll_body(q), pin="0" * 64)
        # The real one still works, once; a second phone is turned away.
        self.assertEqual(phone.post(q, phone.enroll_body(q))[1]["result"], "ok")
        second = FakePhone()
        self.assertEqual(second.post(q, second.enroll_body(q))[0], 409)
        t.join(10)
        self.assertEqual(len(store.devices(self.user)), 1)

    def test_pairing_code_shape(self):
        code = protocol.pairing_code(FakePhone().spki)
        self.assertRegex(code, r"^\d{3} \d{3}$")


if __name__ == "__main__":
    unittest.main()
