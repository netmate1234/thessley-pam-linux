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

    def test_sudo_uid_works_like_pkexec_uid(self):
        rc, out = call(["state"], {"SUDO_UID": str(os.getuid()), "THESSLEY_ADMIN_USER": "root"})
        self.assertEqual((rc, out["user"]), (0, USER))

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


class SwitchesTest(unittest.TestCase):
    """The PAM / greeter edits. Always on copies in a temporary directory, never the real /etc."""

    SUDO = ("#%PAM-1.0\nsession    required   pam_env.so readenv=1\n@include common-auth\n"
            "auth       required   pam_exec.so stdout seteuid /usr/local/lib/thessley-pam/pam-helper\n"
            "@include common-account\n")
    GDM = ("#%PAM-1.0\nauth    requisite       pam_nologin.so\n"
           "auth    requisite       pam_exec.so stdout seteuid /usr/local/lib/thessley-pam/pam-helper --login\n"
           "auth    [success=ok default=ignore module_unknown=ignore]        pam_thessley_authtok.so\n"
           "auth    optional        pam_gnome_keyring.so\n@include common-account\n")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = self.tmp.name
        for name, text in (("sudo", self.SUDO), ("gdm-thessley", self.GDM)):
            with open(os.path.join(self.dir, name), "w") as f:
                f.write(text)
            os.chmod(os.path.join(self.dir, name), 0o640)

    def read(self, name):
        with open(os.path.join(self.dir, name)) as f:
            return f.read()

    def test_sudo_phone_off_and_on(self):
        self.assertEqual(admin_helper.pam_feature_state("sudo-phone", self.dir), "on")
        self.assertEqual(admin_helper.set_pam_feature("sudo-phone", False, self.dir), "off")
        text = self.read("sudo")
        self.assertIn("#thessley-disabled# auth       required   pam_exec.so", text)
        self.assertIn("@include common-auth", text)  # nothing else touched
        self.assertEqual(admin_helper.set_pam_feature("sudo-phone", False, self.dir), "off")  # idempotent
        self.assertEqual(admin_helper.set_pam_feature("sudo-phone", True, self.dir), "on")
        self.assertEqual(self.read("sudo"), self.SUDO)  # back to byte for byte what it was

    def test_keyring_unlock_only_touches_its_own_line(self):
        self.assertEqual(admin_helper.set_pam_feature("keyring-unlock", False, self.dir), "off")
        text = self.read("gdm-thessley")
        self.assertIn("#thessley-disabled# auth    [success=ok", text)
        self.assertIn("auth    requisite       pam_exec.so stdout seteuid /usr/local/lib/thessley-pam/pam-helper --login", text)
        self.assertEqual(admin_helper.pam_feature_state("sudo-phone", self.dir), "on")
        self.assertEqual(admin_helper.set_pam_feature("keyring-unlock", True, self.dir), "on")
        self.assertEqual(self.read("gdm-thessley"), self.GDM)

    def test_mode_is_kept_and_a_backup_is_made_once(self):
        admin_helper.set_pam_feature("sudo-phone", False, self.dir)
        self.assertEqual(os.stat(os.path.join(self.dir, "sudo")).st_mode & 0o7777, 0o640)
        backup = os.path.join(self.dir, "sudo.bak-thessley-admin")
        self.assertEqual(open(backup).read(), self.SUDO)
        admin_helper.set_pam_feature("sudo-phone", True, self.dir)
        admin_helper.set_pam_feature("sudo-phone", False, self.dir)
        self.assertEqual(open(backup).read(), self.SUDO)  # the first original is what is kept

    def test_refuses_to_write_a_file_that_lost_its_essential_line(self):
        with open(os.path.join(self.dir, "sudo"), "w") as f:  # no @include common-auth in this one
            f.write("#%PAM-1.0\nauth       required   pam_exec.so stdout seteuid /usr/local/lib/thessley-pam/pam-helper\n")
        with self.assertRaises(ValueError):
            admin_helper.set_pam_feature("sudo-phone", False, self.dir)
        self.assertNotIn("thessley-disabled", self.read("sudo"))

    def test_absent_when_the_line_or_file_is_missing(self):
        os.unlink(os.path.join(self.dir, "gdm-thessley"))
        self.assertEqual(admin_helper.pam_feature_state("keyring-unlock", self.dir), "absent")
        with open(os.path.join(self.dir, "sudo"), "w") as f:
            f.write("@include common-auth\n")
        self.assertEqual(admin_helper.pam_feature_state("sudo-phone", self.dir), "absent")

    def test_login_qr_in_the_greeter_settings(self):
        g = os.path.join(self.dir, "greeter.dconf-defaults")
        base = "[org/gnome/login-screen]\nlogo=''\n"
        with open(g, "w") as f:
            f.write(base)
        calls = []
        self.assertEqual(admin_helper.login_qr_state(g), "off")
        self.assertEqual(admin_helper.set_login_qr(True, g, lambda: calls.append(1)), "on")
        self.assertEqual(admin_helper.login_qr_state(g), "on")
        self.assertIn("enabled-extensions=['" + admin_helper.UUID + "']", open(g).read())
        self.assertEqual(admin_helper.set_login_qr(False, g, lambda: calls.append(1)), "off")
        self.assertEqual(open(g).read().strip(), base.strip())
        self.assertEqual(len(calls), 2)
        self.assertEqual(admin_helper.set_login_qr(False, g, lambda: calls.append(1)), "off")
        self.assertEqual(len(calls), 2)  # nothing changed, nothing regenerated

    def test_login_qr_will_not_overwrite_an_existing_shell_section(self):
        g = os.path.join(self.dir, "greeter.dconf-defaults")
        with open(g, "w") as f:
            f.write("[org/gnome/shell]\nenabled-extensions=['other@x']\n")
        with self.assertRaises(ValueError):
            admin_helper.set_login_qr(True, g, lambda: None)
        self.assertIn("other@x", open(g).read())


class PhoneSwitchTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        store.BASE = self.tmp.name
        store.USERS = os.path.join(self.tmp.name, "users")
        store.ENROLLED = os.path.join(self.tmp.name, "enrolled")
        self.a = store.add_device(USER, "a2V5", "A", [])["credential_id"]
        self.b = store.add_device(USER, "a2V5", "B", [])["credential_id"]
        self.env = {"THESSLEY_ADMIN_USER": USER}

    def enrolled(self):
        return open(store.ENROLLED).read().split()

    def test_a_switched_off_phone_cannot_approve_but_is_kept(self):
        self.assertEqual(call(["set-phone", self.a, "off"], self.env), (0, {"ok": True}))
        self.assertEqual([d["label"] for d in store.active_devices(USER)], ["B"])
        self.assertEqual([d["label"] for d in store.devices(USER)], ["A", "B"])
        phones = call(["state"], self.env)[1]["phones"]
        self.assertEqual({p["label"]: p["disabled"] for p in phones}, {"A": True, "B": False})
        self.assertEqual(call(["set-phone", self.a, "on"], self.env), (0, {"ok": True}))
        self.assertEqual(len(store.active_devices(USER)), 2)
        self.assertNotIn("disabled", store.devices(USER)[0])

    def test_with_every_phone_off_the_user_is_not_offered_the_qr_code(self):
        self.assertEqual(self.enrolled(), [USER])
        call(["set-phone", self.a, "off"], self.env)
        self.assertEqual(self.enrolled(), [USER])
        call(["set-phone", self.b, "off"], self.env)
        self.assertEqual(self.enrolled(), [])
        call(["set-phone", self.b, "on"], self.env)
        self.assertEqual(self.enrolled(), [USER])

    def test_unknown_phone_and_bad_arguments(self):
        self.assertEqual(call(["set-phone", "c_0000000000000000", "off"], self.env), (0, {"ok": False}))
        for argv in (["set-phone", self.a], ["set-phone", self.a, "maybe"], ["set-phone", "x", "off"],
                     ["set-feature", "x", "on"], ["set-feature", "login-qr", "maybe"], ["set-feature", "../sudo", "off"]):
            self.assertEqual(call(argv, self.env)[0], 2, argv)

    def test_a_disabled_phone_is_not_used_by_the_pam_step(self):
        from thessley_pam import pam
        pam._log = lambda *a, **k: None
        call(["set-phone", self.a, "off"], self.env)
        call(["set-phone", self.b, "off"], self.env)
        env = {"PAM_TYPE": "auth", "PAM_USER": USER, "PAM_SERVICE": "sudo", "PAM_TTY": "/dev/pts/0"}
        self.assertEqual(pam.run(env), pam.OK)                    # sudo: no active phone, no phone step
        self.assertEqual(pam.run(env, login=True), pam.REFUSED)   # login screen: never let in without a phone


class BackendCommandTest(unittest.TestCase):
    def test_sudo_when_it_needs_no_password_else_pkexec(self):
        from thessley_pam import admin_gui
        self.assertEqual(admin_gui.Backend(lambda: True).command("state"), ["sudo", "-n", admin_gui.HELPER, "state"])
        self.assertEqual(admin_gui.Backend(lambda: False).command("set-phone", "c_x", "off"),
                         ["pkexec", admin_gui.HELPER, "set-phone", "c_x", "off"])

    def test_the_choice_is_made_once(self):
        from thessley_pam import admin_gui
        calls = []
        b = admin_gui.Backend(lambda: calls.append(1) or True)
        b.command("state")
        b.command("state")
        self.assertEqual(len(calls), 1)


class PolkitProblemTest(unittest.TestCase):
    def check(self, text):
        d = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, d)
        with open(os.path.join(d, "common-auth"), "w") as f:
            f.write(text)
        from thessley_pam import admin_gui
        return admin_gui.polkit_problem(d)

    def test_yubico_debug_is_reported(self):
        self.assertIn("debug", self.check("auth sufficient pam_yubico.so mode=challenge-response debug\nauth required pam_unix.so\n"))

    def test_fine_configurations_are_not(self):
        self.assertEqual(self.check("auth sufficient pam_yubico.so mode=challenge-response\nauth required pam_unix.so\n"), "")
        self.assertEqual(self.check("#auth sufficient pam_yubico.so mode=challenge-response debug\nauth required pam_unix.so\n"), "")
        self.assertEqual(self.check(""), "")


@unittest.skipUnless(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"), "needs a display (xvfb-run)")
class WindowTest(unittest.TestCase):
    def test_window_with_a_fake_backend(self):
        os.environ["THESSLEY_ADMIN_APP_ID"] = f"se.thessley.PamAdminTest{os.getpid()}"
        from gi.repository import GLib
        from thessley_pam import admin_gui

        phones = [{"credential_id": "c_0123456789abcdef", "label": "Pixel", "enrolled_at": 1700000000, "last_used": None}]
        state = {"user": USER, "phones": phones, "passwordless_sudo": True,
                 "keyring": {"sealed": True, "readable": True, "error": ""},
                 "features": {"login_qr": "on", "sudo_phone": "off", "keyring_unlock": "on"}}

        class Fake:
            removed = []

            def state(self):
                return {**state, "phones": [p for p in phones if p["credential_id"] not in self.removed]}

            def remove_phone(self, cid):
                self.removed.append(cid)
                return {"removed": True}

            def keyring_forget(self):
                return {"forgotten": True}

            def set_phone(self, cid, enabled):
                phones[0]["disabled"] = not enabled
                return {"ok": True}

            def set_feature(self, name, on):
                state["features"][name.replace("-", "_")] = "on" if on else "off"
                return {"state": "on" if on else "off"}

        backend = Fake()
        status = lambda: [("login-qr", "QR code on the login screen", "ok", "Installed."),
                          ("lock-qr", "QR code on your lock screen", "off", "Off."),
                          ("sudo-phone", "Phone approval for sudo", "off", "No."),
                          ("keyring-unlock", "Keyring unlock after a phone login", "ok", "Yes.")]
        problem = lambda: "The administrator password prompt is broken on this computer: test"
        app = admin_gui.AdminApp(backend, status, problem, lambda on: True)
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
        self.assertIn("Administrator sign-in is broken", locked)
        self.assertIn("Sign in to see your phones", locked)
        self.assertNotIn("Pixel", locked)
        self.assertIn("Pixel", unlocked)
        self.assertIn("sudo needs no password", unlocked)
        self.assertIn("Linked", unlocked)
        self.assertNotIn("Pixel", after)
        self.assertIn("No phone is enrolled", after)


if __name__ == "__main__":
    unittest.main()
