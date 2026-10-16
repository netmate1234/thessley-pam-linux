"""The PAM step against the real listener, with a fake phone. No root, no PAM: run() is called directly with
the environment pam_exec would give it. Run from the repo root: python3 -I tests/test_sudo.py
"""

import os
import sys
import tempfile
import threading
import time
import types
import unittest
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_enroll import FakePhone  # noqa: E402
from thessley_pam import pam, protocol, store  # noqa: E402

USER = os.environ.get("USER") or "ubuntu"


class SudoTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        store.BASE = self.tmp.name
        store.USERS = os.path.join(self.tmp.name, "users")
        pam.machine.lan_ip = lambda: "127.0.0.1"
        pam.PORT = 47898
        pam.WAIT = 5
        pam._log = lambda *a, **k: None
        pam._say = lambda text: None
        self.links = []

        def fake_qrencode(cmd, **kw):
            self.links.append(cmd[-1])
            return types.SimpleNamespace(stdout="")
        pam.subprocess = types.SimpleNamespace(run=fake_qrencode)

        self.phone = FakePhone()
        self.device = store.add_device(USER, self.phone.spki, "Test phone", [])
        self.env = {"PAM_TYPE": "auth", "PAM_USER": USER, "PAM_SERVICE": "sudo", "PAM_TTY": "/dev/pts/9"}

    def tearDown(self):
        self.tmp.cleanup()

    def start(self):
        box = {}
        t = threading.Thread(target=lambda: box.setdefault("rc", pam.run(self.env)), daemon=True)
        t.start()
        for _ in range(50):
            if self.links:
                break
            time.sleep(0.1)
        q = {k: v[0] for k, v in parse_qs(urlparse(self.links[0]).query).items()}
        return t, box, q

    def answer(self, q, action="approve", signed_action=None, cred=None, phone=None, ts=None):
        phone = phone or self.phone
        ts = int(time.time()) if ts is None else ts
        msg = protocol.canonical("sudo", q["id"], q["m"], q["u"], q["n"], ts, signed_action or action)
        body = {"credential_id": cred or self.device["credential_id"], "action": action, "timestamp": ts,
                "signature": phone.sign(msg)}
        conn_q = dict(q)
        return _post(conn_q, f"/thessley-pam/v1/sudo/{q['id']}/respond", body)

    def test_approve(self):
        t, box, q = self.start()
        self.assertEqual(self.answer(q)[0], 200)
        t.join(10)
        self.assertEqual(box["rc"], 0)
        self.assertIsNotNone(store.devices(USER)[0]["last_used"])

    def test_deny(self):
        t, box, q = self.start()
        self.assertEqual(self.answer(q, action="deny")[0], 200)
        t.join(10)
        self.assertEqual(box["rc"], 1)

    def test_timeout(self):
        t, box, _ = self.start()
        t.join(10)
        self.assertEqual(box["rc"], 1)

    def test_rejections_then_timeout(self):
        t, box, q = self.start()
        # Signed "deny", sent as "approve".
        self.assertEqual(self.answer(q, action="approve", signed_action="deny")[0], 400)
        # A phone that is not enrolled, claiming the enrolled credential id.
        self.assertEqual(self.answer(q, phone=FakePhone())[0], 400)
        # Unknown credential id.
        self.assertEqual(self.answer(q, cred="c_0000000000000000")[0], 403)
        # Stale timestamp.
        self.assertEqual(self.answer(q, ts=int(time.time()) - 600)[0], 400)
        t.join(10)
        self.assertEqual(box["rc"], 1)

    def test_only_first_answer_counts(self):
        t, box, q = self.start()
        self.assertEqual(self.answer(q, action="deny")[0], 200)
        self.assertEqual(self.answer(q)[0], 409)
        t.join(10)
        self.assertEqual(box["rc"], 1)

    def test_user_without_phone_is_not_affected(self):
        store.remove_device(USER, self.device["credential_id"])
        self.assertEqual(pam.run(self.env), 0)
        self.assertEqual(self.links, [])

    def test_other_pam_steps_pass_through(self):
        self.assertEqual(pam.run(dict(self.env, PAM_TYPE="account")), 0)
        self.assertEqual(self.links, [])


def _post(q, path, body):
    import hashlib
    import http.client
    import json
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    conn = http.client.HTTPSConnection(q["h"], int(q["p"]), context=ctx, timeout=10)
    conn.connect()
    assert hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest() == q["fp"]
    conn.request("POST", path, json.dumps(body), {"Content-Type": "application/json"})
    r = conn.getresponse()
    return r.status, json.loads(r.read())


if __name__ == "__main__":
    unittest.main()
