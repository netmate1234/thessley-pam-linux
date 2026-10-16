"""Phone passes (grace hours), against the real PAM step with a fake phone. No root, no PAM.
Run from the repo root: python3 -I tests/test_grace.py
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
from test_sudo import _post  # noqa: E402
from thessley_pam import grants, pam, protocol, store  # noqa: E402

USER = os.environ.get("USER") or "ubuntu"


class GrantsTest(unittest.TestCase):
    """The pass store on its own."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        store.BASE = os.path.join(self.tmp.name, "etc")
        store.USERS = os.path.join(store.BASE, "users")
        grants.RUN = os.path.join(self.tmp.name, "run")
        grants.GRANTS = os.path.join(grants.RUN, "grants")
        self.now = 1_000_000.0

    def test_default_is_always_ask(self):
        self.assertEqual(grants.grace_hours("sshd"), 0)

    def test_set_and_clear_grace(self):
        grants.set_grace("sshd", 4)
        self.assertEqual(grants.grace_hours("sshd"), 4)
        self.assertEqual(grants.grace_hours("sudo"), 0)  # per service
        grants.set_grace("sshd", 0)
        self.assertEqual(grants.grace_hours("sshd"), 0)

    def test_grace_is_capped_and_bad_names_refused(self):
        grants.set_grace("sshd", 1000)
        self.assertEqual(grants.grace_hours("sshd"), grants.MAX_HOURS)
        for bad in ("", "../x", "a b", ".hidden"):
            with self.assertRaises(ValueError):
                grants.set_grace(bad, 1)

    def test_a_pass_is_for_one_user_service_and_place(self):
        grants.add(USER, "sshd", "10.0.0.5", 4, "c_a", now=self.now)
        ok = lambda **kw: grants.valid(**{"username": USER, "service": "sshd", "rhost": "10.0.0.5",
                                          "active_credentials": {"c_a"}, "now": self.now + 60, **kw})
        self.assertIsNotNone(ok())
        self.assertIsNone(ok(service="sudo"))
        self.assertIsNone(ok(rhost="10.0.0.6"))
        self.assertIsNone(ok(rhost=""))                       # a local login is another place
        self.assertIsNone(ok(active_credentials={"c_b"}))     # the phone that approved is gone or switched off

    def test_expiry_is_fixed_and_exact(self):
        grants.add(USER, "sshd", "10.0.0.5", 4, "c_a", now=self.now)
        args = (USER, "sshd", "10.0.0.5", {"c_a"})
        self.assertIsNotNone(grants.valid(*args, now=self.now + 4 * 3600 - 1))
        self.assertIsNone(grants.valid(*args, now=self.now + 4 * 3600))
        grants.valid(*args, now=self.now + 3600)  # using a pass does not extend it
        self.assertIsNone(grants.valid(*args, now=self.now + 4 * 3600))

    def test_a_new_approval_replaces_the_old_pass_for_the_same_place(self):
        grants.add(USER, "sshd", "10.0.0.5", 1, "c_a", now=self.now)
        grants.add(USER, "sshd", "10.0.0.5", 4, "c_a", now=self.now + 10)
        grants.add(USER, "sshd", "10.0.0.9", 4, "c_a", now=self.now + 10)
        self.assertEqual(len(grants.all_passes(now=self.now + 20)), 2)

    def test_files_are_private(self):
        grants.add(USER, "sshd", "-", 4, "c_a", now=self.now)
        self.assertEqual(os.stat(grants.GRANTS).st_mode & 0o777, 0o700)
        self.assertEqual(os.stat(os.path.join(grants.GRANTS, f"{USER}.json")).st_mode & 0o777, 0o600)

    def test_revoke(self):
        grants.add(USER, "sshd", "10.0.0.5", 4, "c_a", now=self.now)
        grants.add(USER, "sudo", "-", 4, "c_a", now=self.now)
        self.assertEqual(grants.revoke(USER, "sshd"), 1)
        self.assertEqual([p["service"] for p in grants.all_passes(now=self.now + 1)], ["sudo"])
        grants.add(USER, "sudo", "-", 4, "c_a")  # (the real clock, which revoke() without a user uses)
        self.assertEqual(grants.revoke(), 1)
        self.assertEqual(grants.all_passes(), [])

    def test_damaged_files_never_grant_anything(self):
        os.makedirs(grants.GRANTS)
        for text in ("not json", "{}", '[1, "x", {"service": "sshd"}]', '[{"service":"sshd","rhost":"-","credential":"c_a","expires_at":"soon"}]'):
            with open(os.path.join(grants.GRANTS, f"{USER}.json"), "w") as f:
                f.write(text)
            self.assertIsNone(grants.valid(USER, "sshd", "-", {"c_a"}, now=self.now), text)

    def test_unknown_user(self):
        with self.assertRaises(KeyError):
            grants.valid("no-such-user-x", "sshd", "-", set())


class PamPassTest(unittest.TestCase):
    """pam.run with a fake phone: the first login asks, the next ones within the window do not."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        store.BASE = os.path.join(self.tmp.name, "etc")
        store.USERS = os.path.join(store.BASE, "users")
        store.ENROLLED = os.path.join(self.tmp.name, "enrolled")
        grants.RUN = os.path.join(self.tmp.name, "run")
        grants.GRANTS = os.path.join(grants.RUN, "grants")
        pam.machine.lan_ip = lambda: "127.0.0.1"
        pam.PORT = 47897
        pam.WAIT = 3
        pam._log = lambda *a, **k: None
        self.said = []
        pam._say = self.said.append
        self.links = []

        def fake_qrencode(cmd, **kw):
            self.links.append(cmd[-1])
            return types.SimpleNamespace(stdout="")
        pam.subprocess = types.SimpleNamespace(run=fake_qrencode)
        self.phone = FakePhone()
        self.device = store.add_device(USER, self.phone.spki, "Test phone", [])
        self.env = {"PAM_TYPE": "auth", "PAM_USER": USER, "PAM_SERVICE": "sshd", "PAM_RHOST": "192.168.1.50"}
        grants.set_grace("sshd", 4)

    def login(self, answer="approve", env=None):
        """Run one login; returns (exit code, whether the phone was asked)."""
        env = env or self.env
        before = len(self.links)
        box = {}
        t = threading.Thread(target=lambda: box.setdefault("rc", pam.run(env)), daemon=True)
        t.start()
        for _ in range(30):
            if len(self.links) > before or "rc" in box:
                break
            time.sleep(0.05)
        asked = len(self.links) > before
        if asked and answer:
            q = {k: v[0] for k, v in parse_qs(urlparse(self.links[-1]).query).items()}
            ts = int(time.time())
            msg = protocol.canonical("sudo", q["id"], q["m"], q["u"], q["n"], ts, answer)
            body = {"credential_id": self.device["credential_id"], "action": answer, "timestamp": ts, "signature": self.phone.sign(msg)}
            self.assertEqual(_post(q, f"/thessley-pam/v1/sudo/{q['id']}/respond", body)[0], 200)
        t.join(10)
        return box["rc"], asked

    def test_first_login_asks_then_the_next_ones_do_not(self):
        self.assertEqual(self.login(), (0, True))
        self.assertTrue(any("next login from 192.168.1.50 needs no phone for 4 h" in s for s in self.said))
        self.assertEqual(self.login(answer=None), (0, False))
        self.assertTrue(any("approved earlier, valid for another" in s for s in self.said))
        self.assertEqual(self.login(answer=None), (0, False))

    def test_ssh_module_stays_quiet_when_a_pass_is_used(self):
        """sshd prints PAM text twice for a shell login, so the --marker (ssh) mode says nothing on the pass path."""
        self.login()
        self.said.clear()
        self.assertEqual(pam.run(self.env, marker=True), 0)
        self.assertFalse(any("approved earlier" in s for s in self.said))

    def test_a_different_address_asks_again(self):
        self.login()
        self.assertEqual(self.login(env=dict(self.env, PAM_RHOST="192.168.1.77")), (0, True))

    def test_another_service_is_not_covered(self):
        self.login()
        grants.set_grace("sudo", 4)
        self.assertEqual(self.login(env=dict(self.env, PAM_SERVICE="sudo")), (0, True))

    def test_after_the_hours_it_asks_again(self):
        self.login()
        path = os.path.join(grants.GRANTS, f"{USER}.json")
        import json
        items = json.load(open(path))
        items[0]["expires_at"] = int(time.time()) - 1
        json.dump(items, open(path, "w"))
        self.assertEqual(self.login(), (0, True))

    def test_without_grace_hours_every_login_asks(self):
        grants.set_grace("sshd", 0)
        self.assertEqual(self.login(), (0, True))
        self.assertEqual(self.login(), (0, True))
        self.assertEqual(grants.all_passes(), [])

    def test_a_denied_or_unanswered_login_gives_no_pass(self):
        self.assertEqual(self.login(answer="deny"), (1, True))
        self.assertEqual(self.login(answer=None), (1, True))  # times out
        self.assertEqual(grants.all_passes(), [])

    def test_switching_off_the_phone_ends_its_passes_for_good(self):
        self.login()
        store.set_disabled(USER, self.device["credential_id"], True)
        self.assertEqual(grants.all_passes(), [])
        self.assertEqual(self.login(answer=None), (0, False))  # no active phone: no phone step, as for anyone without one
        store.set_disabled(USER, self.device["credential_id"], False)
        self.assertEqual(self.login(), (0, True))               # switching it back on does not revive the old pass

    def test_removing_the_phone_ends_its_passes(self):
        self.login()
        store.remove_device(USER, self.device["credential_id"])
        self.assertEqual(grants.all_passes(), [])

    def test_end_pass_makes_it_ask_again(self):
        self.login()
        self.assertEqual(grants.revoke(USER, "sshd"), 1)
        self.assertEqual(self.login(), (0, True))

    def test_the_login_screen_never_uses_a_pass(self):
        grants.set_grace("gdm-thessley", 4)
        grants.add(USER, "gdm-thessley", "-", 4, self.device["credential_id"])
        self.said.clear()
        box = {}
        env = dict(self.env, PAM_SERVICE="gdm-thessley")
        t = threading.Thread(target=lambda: box.setdefault("rc", pam.run(env, login=True)), daemon=True)
        t.start()
        for _ in range(30):
            if self.said:
                break
            time.sleep(0.05)
        self.assertTrue(self.said and self.said[0].startswith(pam.QR_MARKER))  # asked, pass or not
        t.join(10)

    def test_marker_mode_prints_the_wait_line_after_the_qr_code(self):
        """pam_thessley_phone.so (for sshd) reads the helper's text up to this line."""
        box = {}
        t = threading.Thread(target=lambda: box.setdefault("rc", pam.run(self.env, marker=True)), daemon=True)
        t.start()
        for _ in range(40):
            if pam.WAIT_MARKER in self.said:
                break
            time.sleep(0.05)
        self.assertEqual(self.said[-1], pam.WAIT_MARKER)           # the very last thing printed before it waits
        self.assertTrue(self.said[0].startswith("Approve sshd"))   # the text comes first
        t.join(10)
        self.said.clear()
        self.login(answer=None)
        self.assertNotIn(pam.WAIT_MARKER, self.said)               # never without --marker

    def test_require_phone_refuses_users_without_one(self):
        store.remove_device(USER, self.device["credential_id"])
        self.assertEqual(pam.run(self.env), 0)                    # default: no phone, no phone step (like sudo)
        grants.set_require("sshd", True)
        self.assertEqual(grants.requires_phone("sshd"), True)
        self.assertEqual(grants.requires_phone("sudo"), False)
        self.assertEqual(pam.run(self.env), 1)                    # now refused
        self.assertTrue(any("no phone is enrolled" in s for s in self.said))
        self.assertEqual(pam.run(dict(self.env, PAM_SERVICE="sudo")), 0)  # other services unchanged
        grants.set_require("sshd", False)
        self.assertEqual(pam.run(self.env), 0)

    def test_require_phone_also_covers_a_user_whose_phones_are_all_switched_off(self):
        grants.set_require("sshd", True)
        store.set_disabled(USER, self.device["credential_id"], True)
        self.assertEqual(pam.run(self.env), 1)

    def test_the_text_link_is_shown_only_when_asked_for(self):
        self.login(answer=None)
        self.assertFalse(any(s.startswith("Link: ") for s in self.said))
        os.makedirs(store.BASE, exist_ok=True)
        open(os.path.join(store.BASE, "show-link"), "w").close()
        self.said.clear()
        self.login(answer=None)
        self.assertTrue(any(s.startswith("Link: thessleypam://sudo?") for s in self.said))


class ShowLinkCommandTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        store.BASE = os.path.join(self.tmp.name, "etc")
        store.USERS = os.path.join(store.BASE, "users")
        from thessley_pam import cli
        self.cli = cli
        self.real_geteuid = os.geteuid
        os.geteuid = lambda: 0  # the commands insist on root; the files are in a temporary directory here
        self.addCleanup(setattr, os, "geteuid", self.real_geteuid)

    def test_on_and_off(self):
        flag = os.path.join(store.BASE, "show-link")
        self.assertEqual(self.cli.main(["show-link"]), 0)
        self.assertFalse(os.path.exists(flag))
        self.assertEqual(self.cli.main(["show-link", "on"]), 0)
        self.assertTrue(os.path.exists(flag))
        self.assertEqual(self.cli.main(["show-link", "off"]), 0)
        self.assertFalse(os.path.exists(flag))
        with self.assertRaises(SystemExit):
            self.cli.main(["show-link", "maybe"])


if __name__ == "__main__":
    unittest.main()

    def test_two_logins_at_once_get_different_ports(self):
        """A second login while the first waits must not fail with "Address already in use"."""
        rcs = {}
        for name in ("a", "b"):
            threading.Thread(target=lambda n=name: rcs.setdefault(n, pam.run(dict(self.env, PAM_RHOST="192.168.1.50" if n == "a" else "192.168.1.51"))), daemon=True).start()
            for _ in range(60):
                if len(self.links) > (1 if name == "b" else 0):
                    break
                time.sleep(0.05)
        self.assertEqual(len(self.links), 2)
        ports = [int(parse_qs(urlparse(link).query)["p"][0]) for link in self.links]
        self.assertEqual(ports, [47897, 47898])
        for link in self.links:  # both can be approved
            q = {k: v[0] for k, v in parse_qs(urlparse(link).query).items()}
            ts = int(time.time())
            msg = protocol.canonical("sudo", q["id"], q["m"], q["u"], q["n"], ts, "approve")
            body = {"credential_id": self.device["credential_id"], "action": "approve", "timestamp": ts, "signature": self.phone.sign(msg)}
            self.assertEqual(_post(q, f"/thessley-pam/v1/sudo/{q['id']}/respond", body)[0], 200)
        for _ in range(100):
            if len(rcs) == 2:
                break
            time.sleep(0.05)
        self.assertEqual(rcs, {"a": 0, "b": 0})
