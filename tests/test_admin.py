"""The admin helper's logic (no root needed: it works on a temporary store) and the window with a fake backend.
Run from the repo root:  python3 -I tests/test_admin.py     (the window test needs xvfb-run or a display)
"""

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from thessley_pam import admin_helper, keyring, store  # noqa: E402

USER = os.environ.get("USER") or "ubuntu"


def call(argv, env):
    out = io.StringIO()
    with redirect_stdout(out):
        rc = admin_helper.main(argv, env)
    return rc, json.loads(out.getvalue())


class HelperTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        store.BASE = self.tmp.name
        store.USERS = os.path.join(self.tmp.name, "users")
        store.ENROLLED = os.path.join(self.tmp.name, "enrolled")
        keyring.KEYRING_DIR = os.path.join(self.tmp.name, "keyring")
        self.env = {"THESSLEY_ADMIN_USER": USER}
        self.cred = store.add_device(USER, "a2V5", "Pixel", [])["credential_id"]

    def test_must_be_started_through_pkexec(self):
        rc, out = call(["state"], {})
        self.assertEqual(rc, 1)
        self.assertIn("error", out)

    def test_pkexec_uid_decides_the_account(self):
        rc, out = call(["state"], {"PKEXEC_UID": str(os.getuid()), "THESSLEY_ADMIN_USER": "root"})
        self.assertEqual((rc, out["user"]), (0, USER))  # a variable the caller could set cannot name another user

    def test_state(self):
        rc, out = call(["state"], self.env)
        self.assertEqual(rc, 0)
        self.assertEqual([p["label"] for p in out["phones"]], ["Pixel"])
        self.assertEqual(out["keyring"], {"sealed": False, "readable": False, "error": ""})
        self.assertIsInstance(out["passwordless_sudo"], bool)

    def test_remove_phone(self):
        self.assertEqual(call(["remove-phone", self.cred], self.env), (0, {"removed": True}))
        self.assertEqual(call(["remove-phone", self.cred], self.env), (0, {"removed": False}))
        self.assertEqual(call(["state"], self.env)[1]["phones"], [])

    def test_bad_requests_are_refused(self):
        for argv in ([], ["state", "x"], ["remove-phone"], ["remove-phone", "../../etc/passwd"], ["remove-phone", "c_zz"],
                     ["keyring-forget", "x"], ["format-disk"]):
            rc, out = call(argv, self.env)
            self.assertEqual((rc, out), (2, {"error": "bad request"}), argv)
        self.assertEqual(len(store.devices(USER)), 1)

    def test_keyring_forget(self):
        os.makedirs(keyring.KEYRING_DIR)
        for ext in ("pub", "priv"):
            open(os.path.join(keyring.KEYRING_DIR, f"{USER}.{ext}"), "w").close()
        self.assertTrue(call(["state"], self.env)[1]["keyring"]["sealed"])
        self.assertEqual(call(["keyring-forget"], self.env), (0, {"forgotten": True}))
        self.assertFalse(call(["state"], self.env)[1]["keyring"]["sealed"])

    def test_passwordless_sudo_detection(self):
        d = tempfile.mkdtemp(dir=self.tmp.name)
        write = lambda name, text: open(os.path.join(d, name), "w").write(text)
        write("README", "# nothing here\n")
        write("other", "someoneelse ALL=(ALL) NOPASSWD: ALL\n")
        write("tools", f"{USER} ALL=(root) PASSWD: /usr/bin/apt\n")
        self.assertFalse(admin_helper.passwordless_sudo(USER, d))
        write("mine", f"{USER} ALL=(ALL:ALL) NOPASSWD: ALL\n")
        self.assertTrue(admin_helper.passwordless_sudo(USER, d))
        self.assertFalse(admin_helper.passwordless_sudo(USER, os.path.join(d, "missing")))


@unittest.skipUnless(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"), "needs a display (xvfb-run)")
class WindowTest(unittest.TestCase):
    def test_window_with_a_fake_backend(self):
        os.environ["THESSLEY_ADMIN_APP_ID"] = f"se.thessley.PamAdminTest{os.getpid()}"
        from gi.repository import GLib
        from thessley_pam import admin_gui

        phones = [{"credential_id": "c_0123456789abcdef", "label": "Pixel", "enrolled_at": 1700000000, "last_used": None}]
        state = {"user": USER, "phones": phones, "passwordless_sudo": True,
                 "keyring": {"sealed": True, "readable": True, "error": ""}}

        class Fake:
            removed = []

            def state(self):
                return {**state, "phones": [p for p in phones if p["credential_id"] not in self.removed]}

            def remove_phone(self, cid):
                self.removed.append(cid)
                return {"removed": True}

            def keyring_forget(self):
                return {"forgotten": True}

        backend = Fake()
        status = lambda: [("QR code on the login screen", "ok", "Installed."), ("Phone approval for sudo", "off", "No.")]
        app = admin_gui.AdminApp(backend, status)
        log = []

        def texts(win):
            out = []

            def walk(w):
                c = w.get_first_child()
                while c:
                    if hasattr(c, "get_title") and c.get_title() and not hasattr(c, "get_default_width"):
                        out.append(c.get_title())
                    walk(c)
                    c = c.get_next_sibling()
            walk(win)
            return out

        def step1():
            win = app.props.active_window
            log.append(("locked", texts(win)))
            win.loaded(backend.state())
            return False

        def step2():
            win = app.props.active_window
            log.append(("unlocked", texts(win)))
            win._do(lambda: backend.remove_phone("c_0123456789abcdef"), "Removed.")
            return False

        def step3():
            win = app.props.active_window
            log.append(("after remove", texts(win)))
            app.quit()
            return False

        GLib.timeout_add(500, step1)
        GLib.timeout_add(1200, step2)
        GLib.timeout_add(2200, step3)
        GLib.timeout_add(8000, app.quit)
        app.run([])
        locked, unlocked, after = (dict(log)[k] for k in ("locked", "unlocked", "after remove"))
        self.assertIn("Sign in to see your phones", locked)
        self.assertNotIn("Pixel", locked)
        self.assertIn("Pixel", unlocked)
        self.assertIn("sudo needs no password", unlocked)
        self.assertIn("Linked", unlocked)
        self.assertNotIn("Pixel", after)
        self.assertIn("No phone is enrolled", after)


if __name__ == "__main__":
    unittest.main()
