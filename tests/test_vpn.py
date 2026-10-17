"""The OpenVPN second step: the approval daemon (unix socket + public QR page) and OpenVPN's script, with a fake phone.
Run from the repo root: python3 -I tests/test_vpn.py
"""

import http.client
import json
import os
import socket
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
from thessley_pam import pam, protocol, store, vpn  # noqa: E402

USER = os.environ.get("USER") or "ubuntu"
SETTINGS = {"enabled": True, "public_host": "vpn.example.org", "page_port": 47831, "socket_group": "", "wait": 8}


class VpnBase(unittest.TestCase):
    next_port = 47600

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.saved = (store.BASE, store.USERS, store.ENROLLED, pam.machine.lan_ip, pam.PORT, pam._log, pam._say, pam.subprocess)
        self.addCleanup(self.restore)
        store.BASE = self.tmp.name
        store.USERS = os.path.join(self.tmp.name, "users")
        store.ENROLLED = os.path.join(self.tmp.name, "enrolled")
        pam.machine.lan_ip = lambda: "127.0.0.1"
        VpnBase.next_port += 10
        pam.PORT = VpnBase.next_port
        pam._log = lambda *a, **k: None
        pam._say = lambda text: None
        pam.subprocess = types.SimpleNamespace(run=lambda cmd, **kw: types.SimpleNamespace(stdout=""))
        self.phone = FakePhone()
        self.device = store.add_device(USER, self.phone.spki, "Test phone", [])
        self.approvals = vpn.Approvals(settings=lambda: SETTINGS)
        self.sock_path = os.path.join(self.tmp.name, "vpn.sock")
        self.server = vpn.make_socket_server(self.approvals, self.sock_path)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.shutdown)
        self.addCleanup(self.server.server_close)

    def restore(self):
        (store.BASE, store.USERS, store.ENROLLED, pam.machine.lan_ip, pam.PORT, pam._log, pam._say, pam.subprocess) = self.saved

    def ask(self, user=USER, rhost="203.0.113.7"):
        """What OpenVPN's script (or its deferred child) does: one request, then lines until the verdict."""
        conn = socket.socket(socket.AF_UNIX)
        conn.settimeout(30)
        conn.connect(self.sock_path)
        f = conn.makefile("rw", encoding="utf-8")
        f.write(json.dumps({"user": user, "rhost": rhost}) + "\n")
        f.flush()
        return conn, f, lambda: json.loads(f.readline())

    def answer(self, link, action="approve"):
        q = {k: v[0] for k, v in parse_qs(urlparse(link).query).items()}
        ts = int(time.time())
        msg = protocol.canonical("vpn", q["id"], q["m"], q["u"], q["n"], ts, action)
        body = {"credential_id": self.device["credential_id"], "action": action, "timestamp": ts, "signature": self.phone.sign(msg)}
        # the link names the public host; this test machine reaches the listener on its own address
        return q, _post(dict(q, h="127.0.0.1"), f"/thessley-pam/v1/vpn/{q['id']}/respond", body)

    def flow_link(self):
        for _ in range(50):
            flows = list(self.approvals.flows.values())
            if flows and flows[0].link:
                return flows[0].link
            time.sleep(0.1)
        self.fail("no approval link appeared")


class DaemonTest(VpnBase):
    def test_a_device_approval_lets_the_login_through(self):
        conn, f, read = self.ask()
        self.addCleanup(conn.close)
        msg = read()
        self.assertTrue(msg["url"].startswith("https://vpn.example.org:47831/vpn/"), msg)
        self.assertEqual(msg["timeout"], 8)
        q, (code, _) = self.answer(self.flow_link())
        self.assertEqual(code, 200)
        self.assertEqual(q["h"], "vpn.example.org")      # the device is told the public name, not the LAN address
        self.assertEqual(q["s"], "openvpn")
        self.assertTrue(self.flow_link().startswith("thessleypam://vpn?"))      # a type of its own, signed as such
        self.assertEqual(q["r"], "203.0.113.7")
        done = read()
        self.assertEqual((done["done"], done["ok"]), (True, True))

    def test_a_denial_refuses_the_login(self):
        conn, f, read = self.ask()
        self.addCleanup(conn.close)
        read()
        self.answer(self.flow_link(), "deny")
        done = read()
        self.assertEqual(done["ok"], False)
        self.assertIn("denied", done["reason"])

    def test_no_answer_in_time_refuses_the_login(self):
        SETTINGS_SHORT = dict(SETTINGS, wait=2)
        self.approvals.settings = lambda: SETTINGS_SHORT
        pam.WAIT = 2
        conn, f, read = self.ask()
        self.addCleanup(conn.close)
        read()
        done = read()
        self.assertEqual(done["ok"], False)
        self.assertIn("in time", done["reason"])

    def test_unknown_or_deviceless_or_odd_account_names_are_refused_at_once(self):
        for user, why in (("no_such_user_xyz", "No such account"), ("../etc", "not an account name"), ("", "not an account name"),
                          ("root", "no device")):
            conn, f, read = self.ask(user)
            self.addCleanup(conn.close)
            done = read()
            self.assertEqual(done["ok"], False, user)
            self.assertIn(why.lower(), done["reason"].lower(), user)

    def test_garbage_on_the_socket_is_refused(self):
        conn = socket.socket(socket.AF_UNIX)
        conn.settimeout(10)
        conn.connect(self.sock_path)
        self.addCleanup(conn.close)
        conn.sendall(b"not json\n")
        done = json.loads(conn.makefile().readline())
        self.assertEqual(done["ok"], False)

    def test_a_retrying_client_joins_the_approval_already_waiting(self):
        conn, f, read = self.ask()
        self.addCleanup(conn.close)
        first = read()["url"]
        conn2, f2, read2 = self.ask()                  # the same account from the same address, a few seconds later
        self.addCleanup(conn2.close)
        self.assertEqual(read2()["url"], first)        # the same page and QR code, not a second approval
        self.assertEqual(len(self.approvals.flows), 1)
        self.answer(self.flow_link())
        self.assertEqual(read()["ok"], True)
        self.assertEqual(read2()["ok"], True)          # one answer lets both through
        conn3, f3, read3 = self.ask(rhost="198.51.100.9")   # another address is another approval
        self.addCleanup(conn3.close)
        self.assertNotEqual(read3()["url"], first)

    def test_a_pass_from_an_earlier_approval_needs_no_new_one(self):
        runner_calls = []
        self.approvals.runner = lambda env, say, wait, **kw: (runner_calls.append((env, kw)), pam.OK)[1]
        conn, f, read = self.ask()
        self.addCleanup(conn.close)
        done = read()
        self.assertEqual((done["done"], done["ok"]), (True, True))      # no url step at all
        self.assertEqual(runner_calls[0][0]["PAM_PUBLIC_HOST"], "vpn.example.org")
        self.assertEqual(runner_calls[0][0]["PAM_SERVICE"], "openvpn")
        self.assertEqual(runner_calls[0][1]["req_type"], "vpn")


class EnrolTest(VpnBase):
    def test_a_vpn_enrolment_link_carries_the_public_host(self):
        from thessley_pam import cli
        saw = []
        cli.machine.lan_ip = lambda: "127.0.0.1"
        t = threading.Thread(target=lambda: cli._enroll_flow(USER, 47690, say=saw.append, ask_yes=lambda p, t: False,
                                                             enroll_wait=3, link_extra={"vh": "vpn.example.org"}), daemon=True)
        t.start()
        for _ in range(50):
            if any("Link:" in s for s in saw):
                break
            time.sleep(0.1)
        link = [s for s in saw if "Link:" in s][0].split("Link: ")[1].strip()
        q = {k: v[0] for k, v in parse_qs(urlparse(link).query).items()}
        self.assertEqual(q["vh"], "vpn.example.org")
        self.assertEqual(q["h"], "127.0.0.1")          # the enrolment itself still happens on the local network
        t.join(10)

    def test_a_plain_enrolment_has_no_public_host(self):
        from thessley_pam import cli
        saw = []
        cli.machine.lan_ip = lambda: "127.0.0.1"
        t = threading.Thread(target=lambda: cli._enroll_flow(USER, 47691, say=saw.append, ask_yes=lambda p, t: False, enroll_wait=3), daemon=True)
        t.start()
        for _ in range(50):
            if any("Link:" in s for s in saw):
                break
            time.sleep(0.1)
        self.assertNotIn("vh=", [s for s in saw if "Link:" in s][0])
        t.join(10)


class PortsTest(unittest.TestCase):
    def test_the_vpn_uses_only_the_forwarded_approval_port_by_default(self):
        old = pam.PORT, pam.PORT_TRIES
        try:
            vpn.apply_ports(vpn.grants.vpn_settings())
            self.assertEqual((pam.PORT, pam.PORT_TRIES), (47810, 1))
            vpn.apply_ports({"approval_port": 47850, "approval_tries": 3})
            self.assertEqual((pam.PORT, pam.PORT_TRIES), (47850, 3))
        finally:
            pam.PORT, pam.PORT_TRIES = old

    def test_a_busy_forwarded_port_is_a_refusal_not_a_port_nobody_can_reach(self):
        # port taken by another approval: with one try the next-free-port walk must not happen
        import socket as _s
        hog = _s.socket()
        hog.bind(("127.0.0.1", 0))
        hog.listen()
        port = hog.getsockname()[1]
        self.addCleanup(hog.close)
        from thessley_pam import listener
        with self.assertRaises(OSError):
            with listener.listening("127.0.0.1", {}, port, 1):
                pass


class ScriptTest(VpnBase):
    """OpenVPN's auth-user-pass-verify: exit codes and the files it writes."""

    def env(self, **extra):
        e = {"username": USER, "common_name": USER, "untrusted_ip": "203.0.113.7",
             "auth_control_file": os.path.join(self.tmp.name, "acf"), "auth_pending_file": os.path.join(self.tmp.name, "apf"),
             "auth_failed_reason_file": os.path.join(self.tmp.name, "afr")}
        e.update(extra)
        return e

    def test_a_certificate_for_another_name_is_rejected_without_asking_anyone(self):
        env = self.env(common_name="mallory")
        self.assertEqual(vpn.authenticate(env, self.sock_path, log=lambda t: None), 1)
        self.assertEqual(self.approvals.flows, {})
        self.assertIn("mallory", open(env["auth_failed_reason_file"]).read())

    def test_a_bad_account_name_is_rejected(self):
        for name in ("", "Ro ot", "a/b", "x" * 40):
            self.assertEqual(vpn.authenticate(self.env(username=name, common_name=name), self.sock_path, log=lambda t: None), 1, name)

    def test_the_daemon_not_running_is_a_rejection(self):
        self.assertEqual(vpn.authenticate(self.env(), os.path.join(self.tmp.name, "nothing.sock"), log=lambda t: None), 1)

    def test_it_defers_with_the_pending_file_and_the_child_writes_the_verdict(self):
        env = self.env()
        forks = []
        rc = vpn.authenticate(env, self.sock_path, fork=lambda: (forks.append(1), 4242)[1], log=lambda t: None)
        self.assertEqual(rc, 2)                                           # deferred: the parent returns while the child waits
        timeout, method, url = open(env["auth_pending_file"]).read().split("\n")[:3]
        self.assertEqual((timeout, method), ("8", "openurl"))
        self.assertTrue(url.startswith("https://vpn.example.org:47831/vpn/"))
        self.assertFalse(os.path.exists(env["auth_control_file"]))        # nothing decided yet

    def test_the_child_writes_1_for_an_approval_and_0_with_the_reason_for_a_refusal(self):
        control, reason = os.path.join(self.tmp.name, "c1"), os.path.join(self.tmp.name, "r1")
        self.assertTrue(vpn.finish(lambda: {"done": True, "ok": True}, control, reason))
        self.assertEqual(open(control).read(), "1")
        control, reason = os.path.join(self.tmp.name, "c0"), os.path.join(self.tmp.name, "r0")
        self.assertFalse(vpn.finish(lambda: {"done": True, "ok": False, "reason": "Nobody approved in time."}, control, reason))
        self.assertEqual(open(control).read(), "0")
        self.assertEqual(open(reason).read(), "Nobody approved in time.")

    def test_a_vanished_daemon_means_reject(self):
        def gone():
            raise OSError("hung up")
        control = os.path.join(self.tmp.name, "cx")
        self.assertFalse(vpn.finish(gone, control, None))
        self.assertEqual(open(control).read(), "0")

    def test_an_openvpn_without_deferred_authentication_waits_in_the_script(self):
        env = self.env()
        del env["auth_control_file"], env["auth_pending_file"]
        box = {}
        t = threading.Thread(target=lambda: box.setdefault("rc", vpn.authenticate(env, self.sock_path, log=lambda t: None)), daemon=True)
        t.start()
        self.answer(self.flow_link())
        t.join(20)
        self.assertEqual(box["rc"], 0)

    def test_end_to_end_with_a_pass_exits_0_straight_away(self):
        self.approvals.runner = lambda env, say, wait, **kw: pam.OK
        self.assertEqual(vpn.authenticate(self.env(), self.sock_path, log=lambda t: None), 0)


class PageTest(VpnBase):
    """The public QR page. Plain HTTP here; the daemon wraps the same handler in TLS."""

    def setUp(self):
        super().setUp()
        self.httpd = vpn.ThreadingHTTPServer(("127.0.0.1", 0), vpn.make_page_handler(self.approvals, lambda link: b"<svg/>"))
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addCleanup(self.httpd.shutdown)
        self.addCleanup(self.httpd.server_close)

    def get(self, path):
        c = http.client.HTTPConnection("127.0.0.1", self.httpd.server_address[1], timeout=10)
        c.request("GET", path)
        r = c.getresponse()
        return r.status, dict(r.getheaders()), r.read().decode(errors="replace")

    def test_the_page_shows_the_qr_and_the_link_and_follows_the_outcome(self):
        conn, f, read = self.ask()
        self.addCleanup(conn.close)
        url = read()["url"]
        fid = url.rsplit("/", 1)[1]
        status, headers, body = self.get(f"/vpn/{fid}")
        self.assertEqual(status, 200)
        self.assertIn(f"/vpn/{fid}.svg", body)
        self.assertIn("thessleypam://", body)
        self.assertNotIn('http-equiv="refresh"', body)            # a page that reloads itself makes the QR code flicker
        self.assertIn(f'fetch("/vpn/{fid}.json"', body)             # it asks for the state instead
        nonce = headers["Content-Security-Policy"].split("'nonce-")[1].split("'")[0]
        self.assertIn(f'<script nonce="{nonce}">', body)
        self.assertIn("default-src 'none'", headers["Content-Security-Policy"])
        self.assertEqual(json.loads(self.get(f"/vpn/{fid}.json")[2]), {"finished": False, "has_link": True})
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(self.get(f"/vpn/{fid}.svg")[0], 200)
        self.answer(self.flow_link())
        read()
        status, _, body = self.get(f"/vpn/{fid}")
        self.assertIn("Approved", body)
        self.assertNotIn("<script", body)
        self.assertEqual(json.loads(self.get(f"/vpn/{fid}.json")[2])["finished"], True)

    def test_unknown_or_malformed_addresses_are_404(self):
        for path in ("/", "/vpn/", "/vpn/" + "0" * 32, "/vpn/../etc/passwd", "/vpn/" + "g" * 32, "/vpn/" + "0" * 32 + ".svg"):
            self.assertEqual(self.get(path)[0], 404, path)

    def test_a_refused_login_says_so_on_the_page(self):
        conn, f, read = self.ask()
        self.addCleanup(conn.close)
        fid = read()["url"].rsplit("/", 1)[1]
        self.answer(self.flow_link(), "deny")
        read()
        self.assertIn("Not approved", self.get(f"/vpn/{fid}")[2])


if __name__ == "__main__":
    unittest.main(verbosity=2)
