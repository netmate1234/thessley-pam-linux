"""The admin web page, against a real HTTPS server on 127.0.0.1 and a fake phone that signs approvals.
No root, no PAM, no browser. Run from the repo root:  python3 -I -m pytest tests/test_web.py
"""

import http.client
import json
import os
import re
import ssl
import sys
import tempfile
import threading
import time
import types
import unittest
from urllib.parse import parse_qs, urlencode, urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_enroll import FakePhone  # noqa: E402
from test_sudo import _post  # noqa: E402
from thessley_pam import cli, grants, pam, protocol, store, web  # noqa: E402

USER = os.environ.get("USER") or "ubuntu"
OTHER = "root"  # an account that exists on every machine, used as "someone else"


class Browser:
    """A very small browser: keeps cookies, does not follow redirects on its own."""

    def __init__(self, port: int):
        self.port = port
        self.cookies: dict[str, str] = {}

    def request(self, method: str, path: str, data: dict | None = None):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection("127.0.0.1", self.port, context=ctx, timeout=20)
        headers = {}
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        body = None
        if data is not None:
            body = urlencode(data)
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        conn.request(method, path, body, headers)
        resp = conn.getresponse()
        raw = resp.read()
        for name, value in resp.getheaders():
            if name.lower() == "set-cookie":
                k, v = value.split(";", 1)[0].split("=", 1)
                if v == "" or "Max-Age=0" in value:
                    self.cookies.pop(k, None)
                else:
                    self.cookies[k] = v
        conn.close()
        return resp, raw.decode("utf-8", "replace")

    def get(self, path):
        return self.request("GET", path)

    def post(self, path, data=None):
        return self.request("POST", path, data or {})


class WebBase(unittest.TestCase):
    """The server, the fake phone and the helpers; the tests are in WebTest and KeyDetailsTest."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        store.BASE = os.path.join(self.tmp.name, "etc")
        store.USERS = os.path.join(store.BASE, "users")
        store.ENROLLED = os.path.join(self.tmp.name, "enrolled")
        grants.RUN = os.path.join(self.tmp.name, "run")
        grants.GRANTS = os.path.join(grants.RUN, "grants")
        # the PAM step and the enrolment, as in the other tests
        pam.machine.lan_ip = lambda: "127.0.0.1"
        cli.machine.lan_ip = lambda: "127.0.0.1"
        pam.PORT = 47850
        cli.DEFAULT_PORT = 47860
        pam.WAIT = 6
        pam._log = lambda *a, **k: None
        self.links = []
        pam.subprocess = types.SimpleNamespace(run=lambda cmd, **kw: (self.links.append(cmd[-1]), types.SimpleNamespace(stdout=""))[1])
        self.admin = False
        web.is_admin = lambda name: self.admin
        self.phone = FakePhone()
        self.device = store.add_device(USER, self.phone.spki, "My phone", [])
        self.app = web.WebApp(journal=lambda: [], qr=lambda link: b"<svg xmlns='http://www.w3.org/2000/svg'/>")
        cert, key = os.path.join(self.tmp.name, "c.pem"), os.path.join(self.tmp.name, "k.pem")
        web.ensure_cert(cert, key, ["127.0.0.1"])
        self.httpd = web.make_server(self.app, "127.0.0.1", 0, cert, key)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addCleanup(self.httpd.shutdown)
        self.addCleanup(self.httpd.server_close)
        self.b = Browser(self.port)

    # -- helpers
    def wait_for(self, browser, flow_id, want, timeout=15):
        end = time.time() + timeout
        last = {}
        while time.time() < end:
            _, body = browser.get(f"/status/{flow_id}")
            last = json.loads(body)
            if want(last):
                return last
            time.sleep(0.15)
        self.fail(f"the page never reached the wanted state; last status {last}")

    def approve(self, link, phone=None, action="approve", device=None, signed=True):
        q = {k: v[0] for k, v in parse_qs(urlparse(link).query).items()}
        phone = phone or self.phone
        ts = int(time.time())
        msg = protocol.canonical("sudo", q["id"], q["m"], q["u"], q["n"], ts, action)
        body = {"credential_id": (device or self.device)["credential_id"], "action": action, "timestamp": ts}
        if signed:
            body["signature"] = phone.sign(msg)
        else:
            body["nonce"] = q["n"]
        return q, _post(q, f"/thessley-pam/v1/sudo/{q['id']}/respond", body)

    def start_flow(self, browser, path, data):
        resp, _ = browser.post(path, data)
        self.assertEqual(resp.status, 303, path)
        loc = resp.getheader("Location")
        m = re.fullmatch(r"/wait/([0-9a-f]{32})", loc)
        self.assertIsNotNone(m, loc)
        return m.group(1)

    def login(self, browser=None, answer="approve"):
        browser = browser or self.b
        fid = self.start_flow(browser, "/login", {"user": USER})
        status = self.wait_for(browser, fid, lambda s: s.get("link"))
        self.approve(status["link"], action=answer)
        if answer == "approve":
            self.wait_for(browser, fid, lambda s: s.get("next"))
        else:
            self.wait_for(browser, fid, lambda s: s["state"] in ("refused", "timeout"))
        return fid

    def csrf(self, browser=None):
        _, body = (browser or self.b).get("/keys")
        return re.search(r'name="csrf" value="([^"]+)"', body).group(1)

    def step_up(self, path, data, browser=None, answer="approve"):
        """Do a change that needs a fresh approval; return the final status."""
        browser = browser or self.b
        data = dict(data, csrf=self.csrf(browser))
        fid = self.start_flow(browser, path, data)
        status = self.wait_for(browser, fid, lambda s: s.get("link"))
        self.approve(status["link"], action=answer)
        if answer == "approve":
            return fid, self.wait_for(browser, fid, lambda s: s.get("next"))
        return fid, self.wait_for(browser, fid, lambda s: s["state"] in ("refused", "timeout"))


class WebTest(WebBase):
    # -- sign-in
    def test_sign_in_with_a_phone_approval_opens_the_page(self):
        self.assertEqual(self.b.get("/keys")[0].status, 303)  # not signed in: sent to the sign-in page
        self.login()
        resp, body = self.b.get("/keys")
        self.assertEqual(resp.status, 200)
        self.assertIn("My phone", body)
        self.assertIn(self.device["credential_id"], body)

    def test_the_session_cookie_is_locked_down(self):
        fid = self.start_flow(self.b, "/login", {"user": USER})
        status = self.wait_for(self.b, fid, lambda s: s.get("link"))
        self.approve(status["link"])
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection("127.0.0.1", self.port, context=ctx, timeout=10)
        for _ in range(60):
            conn.request("GET", f"/status/{fid}", headers={"Cookie": f"thessley_wait={self.b.cookies['thessley_wait']}"})
            r = conn.getresponse()
            data = r.read()
            cookies = [v for k, v in r.getheaders() if k.lower() == "set-cookie" and v.startswith("thessley_session=")]
            if cookies:
                break
            time.sleep(0.2)
        self.assertTrue(cookies)
        for flag in ("HttpOnly", "Secure", "SameSite=Strict"):
            self.assertIn(flag, cookies[0])

    def test_a_denied_sign_in_gives_no_session(self):
        self.login(answer="deny")
        self.assertNotIn("thessley_session", self.b.cookies)
        self.assertEqual(self.b.get("/keys")[0].status, 303)

    def test_deny_without_a_signature_also_ends_the_sign_in(self):
        fid = self.start_flow(self.b, "/login", {"user": USER})
        status = self.wait_for(self.b, fid, lambda s: s.get("link"))
        _, (code, reply) = self.approve(status["link"], action="deny", signed=False)
        self.assertEqual(code, 200)
        self.wait_for(self.b, fid, lambda s: s["state"] == "refused")
        self.assertNotIn("thessley_session", self.b.cookies)

    def test_unsigned_approval_never_signs_anyone_in(self):
        fid = self.start_flow(self.b, "/login", {"user": USER})
        status = self.wait_for(self.b, fid, lambda s: s.get("link"))
        _, (code, _) = self.approve(status["link"], action="approve", signed=False)
        self.assertEqual(code, 400)
        self.assertNotIn("thessley_session", self.b.cookies)

    def test_no_answer_in_time_is_a_refusal(self):
        fid = self.start_flow(self.b, "/login", {"user": USER})
        self.wait_for(self.b, fid, lambda s: s["state"] == "timeout", timeout=20)
        self.assertNotIn("thessley_session", self.b.cookies)

    def test_unknown_accounts_and_accounts_without_a_key_look_the_same(self):
        store.remove_device(USER, self.device["credential_id"])
        for name in (USER, "no-such-user-x", "", "../etc", "ROOT; rm"):
            resp, body = self.b.post("/login", {"user": name})
            self.assertEqual(resp.status, 200, name)
            self.assertIn("cannot sign in here", body)
        self.assertEqual(self.app.flows, {})

    def test_another_browser_cannot_take_over_a_sign_in(self):
        fid = self.start_flow(self.b, "/login", {"user": USER})
        status = self.wait_for(self.b, fid, lambda s: s.get("link"))
        self.approve(status["link"])
        thief = Browser(self.port)  # knows the request id from somewhere, but not the cookie
        self.assertEqual(json.loads(thief.get(f"/status/{fid}")[1])["state"], "gone")
        self.assertEqual(thief.get(f"/qr/{fid}.svg")[0].status, 404)

    def test_sign_in_requests_are_rate_limited(self):
        statuses = [self.b.post("/login", {"user": "no-such-user-x"})[0].status for _ in range(web.LOGIN_RATE[0] + 2)]
        self.assertIn(429, statuses)

    def test_the_wait_page_offers_an_open_in_the_app_button(self):
        """The browser's own app can be opened with the request: a thessleypam:// button next to the QR code and the text link."""
        fid = self.start_flow(self.b, "/login", {"user": USER})
        _, page = self.b.get(f"/wait/{fid}")
        self.assertIn("Open this request in the Thessley app", page)
        self.assertIn("startsWith('thessleypam://')", page)       # only ever a link of this kind becomes the button
        self.assertIn(".btn{", page)                                # and it is styled as a button
        status = self.wait_for(self.b, fid, lambda s: s.get("link"))
        self.assertTrue(status["link"].startswith("thessleypam://"))

    def test_every_page_has_an_open_the_app_button(self):
        """A button that opens the Thessley app on whatever this browser runs on, even where there is no request to answer."""
        for path in ("/", "/nowhere"):
            _, body = self.b.get(path)
            self.assertIn('href="thessleypam://open"', body, path)
            self.assertIn("Open the Thessley app", body, path)
        self.login()
        for path in ("/keys", "/log", "/admin"):
            _, body = self.b.get(path)
            self.assertIn('href="thessleypam://open"', body, path)

    def test_every_page_has_the_security_headers(self):
        resp, _ = self.b.get("/")
        csp = resp.getheader("Content-Security-Policy")
        self.assertIn("default-src 'none'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertEqual(resp.getheader("X-Content-Type-Options"), "nosniff")
        self.assertEqual(resp.getheader("Cache-Control"), "no-store")

    # -- changes need a fresh approval
    def test_renaming_asks_the_phone_first(self):
        self.login()
        cred = self.device["credential_id"]
        csrf = self.csrf()
        fid = self.start_flow(self.b, "/keys/rename", {"csrf": csrf, "user": USER, "cred": cred, "label": "Work phone"})
        self.assertEqual(store.devices(USER)[0]["label"], "My phone")     # nothing happens before the approval
        status = self.wait_for(self.b, fid, lambda s: s.get("link"))
        self.approve(status["link"])
        self.wait_for(self.b, fid, lambda s: s.get("next"))
        self.assertEqual(store.devices(USER)[0]["label"], "Work phone")
        self.assertIn("Work phone", self.b.get("/keys")[1])

    def test_a_denied_change_changes_nothing(self):
        self.login()
        self.step_up("/keys/remove", {"user": USER, "cred": self.device["credential_id"]}, answer="deny")
        self.assertEqual(len(store.devices(USER)), 1)

    def test_switch_off_and_on_and_remove(self):
        self.login()
        cred = self.device["credential_id"]
        self.step_up("/keys/disable", {"user": USER, "cred": cred})
        self.assertTrue(store.devices(USER)[0].get("disabled"))
        store.set_disabled(USER, cred, False)  # the only key is off now, so nothing could approve switching it on: undo by hand
        self.step_up("/keys/remove", {"user": USER, "cred": cred})
        self.assertEqual(store.devices(USER), [])

    def test_a_form_without_the_right_token_is_refused(self):
        self.login()
        for token in ("", "wrong"):
            resp, _ = self.b.post("/keys/remove", {"csrf": token, "user": USER, "cred": self.device["credential_id"]})
            self.assertEqual(resp.status, 400)
        self.assertEqual(len(store.devices(USER)), 1)

    def test_a_bad_key_id_or_label_is_refused(self):
        self.login()
        csrf = self.csrf()
        self.assertEqual(self.b.post("/keys/remove", {"csrf": csrf, "user": USER, "cred": "../../etc"})[0].status, 404)
        self.assertEqual(self.b.post("/keys/rename", {"csrf": csrf, "user": USER, "cred": self.device["credential_id"], "label": "<script>"})[0].status, 400)

    def test_signing_out(self):
        self.login()
        self.b.post("/logout", {"csrf": self.csrf()})
        self.assertEqual(self.b.get("/keys")[0].status, 303)

    def test_a_session_ends_when_idle_too_long(self):
        self.login()
        for s in self.app.sessions.values():
            s.last -= s.minutes * 60 + 5
        self.assertEqual(self.b.get("/keys")[0].status, 303)

    # -- adding a key
    def test_adding_a_phone_from_the_page(self):
        self.login()
        fid, _ = self.step_up("/keys/add", {"user": USER})
        # step_up waited for the approval; the page then moves on to the enrolment
        _, body = self.b.get("/keys")
        loc = None
        for flow in list(self.app.flows.values()):
            if flow.kind == "enroll":
                loc = flow
        self.assertIsNotNone(loc)
        status = self.wait_for(self.b, loc.id, lambda s: s.get("link"))
        q = {k: v[0] for k, v in parse_qs(urlparse(status["link"]).query).items()}
        self.assertEqual(q["u"], USER)
        new = FakePhone()
        threading.Thread(target=lambda: new.post(q, new.enroll_body(q)), daemon=True).start()
        status = self.wait_for(self.b, loc.id, lambda s: s["state"] == "confirm")
        self.assertRegex(status["code"], r"^\d{3} \d{3}$")
        self.b.post(f"/enroll/{loc.id}/confirm", {"csrf": self.csrf(), "answer": "yes"})
        self.wait_for(self.b, loc.id, lambda s: s.get("next"))
        self.assertEqual(len(store.devices(USER)), 2)

    def test_the_codes_not_matching_adds_nothing(self):
        self.login()
        self.step_up("/keys/add", {"user": USER})
        flow = [f for f in self.app.flows.values() if f.kind == "enroll"][0]
        status = self.wait_for(self.b, flow.id, lambda s: s.get("link"))
        q = {k: v[0] for k, v in parse_qs(urlparse(status["link"]).query).items()}
        new = FakePhone()
        threading.Thread(target=lambda: new.post(q, new.enroll_body(q)), daemon=True).start()
        self.wait_for(self.b, flow.id, lambda s: s["state"] == "confirm")
        self.b.post(f"/enroll/{flow.id}/confirm", {"csrf": self.csrf(), "answer": "no"})
        self.wait_for(self.b, flow.id, lambda s: s["state"] == "failed")
        self.assertEqual(len(store.devices(USER)), 1)

    # -- who may do what
    def test_a_normal_user_sees_only_their_own_keys_and_no_admin_page(self):
        self.login()
        self.assertEqual(self.b.get(f"/keys?user={OTHER}")[0].status, 403)
        self.assertEqual(self.b.get("/admin")[0].status, 403)
        self.assertEqual(self.b.post("/admin/set", {"csrf": self.csrf(), "name": "require", "value": "on"})[0].status, 403)
        self.assertFalse(grants.requires_phone("sshd"))

    def test_an_administrator_can_open_the_settings_and_change_one_with_an_approval(self):
        self.admin = True
        self.login()
        resp, body = self.b.get("/admin")
        self.assertEqual(resp.status, 200)
        self.assertIn("Settings for this computer", body)
        self.step_up("/admin/set", {"name": "require", "value": "on"})
        self.assertTrue(grants.requires_phone("sshd"))
        self.step_up("/admin/set", {"name": "grace", "value": "2"})
        self.assertEqual(grants.grace_hours("sshd"), 2)
        self.step_up("/admin/set", {"name": "self_enroll", "value": "off"})
        self.assertFalse(grants.self_enroll_allowed())
        self.step_up("/admin/set", {"name": "show_link", "value": "off"})
        self.assertFalse(store.show_link())

    def test_admin_settings_are_validated(self):
        self.admin = True
        self.login()
        csrf = self.csrf()
        self.assertEqual(self.b.post("/admin/set", {"csrf": csrf, "name": "grace", "value": "-3"})[0].status, 400)
        self.assertEqual(self.b.post("/admin/set", {"csrf": csrf, "name": "grace", "value": "abc"})[0].status, 400)
        self.assertEqual(self.b.post("/admin/set", {"csrf": csrf, "name": "require", "value": "maybe"})[0].status, 400)
        self.assertEqual(self.b.post("/admin/set", {"csrf": csrf, "name": "rm -rf", "value": "on"})[0].status, 404)

    # -- output safety and the log
    def test_nothing_from_the_key_list_reaches_the_page_unescaped(self):
        store.add_device(USER, FakePhone().spki, "<img src=x onerror=alert(1)>", [])
        self.login()
        _, body = self.b.get("/keys")
        self.assertNotIn("<img src=x", body)
        self.assertIn("&lt;img src=x", body)

    def test_the_activity_log_shows_my_account_only(self):
        lines = [
            f"2026-10-17T01:14:10+02:00 host thessley-pam[1]: approved by 'My phone' (c_0123456789abcdef) from 192.168.1.5 for {USER} (sshd, ssh)",
            "2026-10-17T01:15:00+02:00 host thessley-pam[2]: timeout for somebody-else (sshd, ssh)",
            f"2026-10-17T01:16:00+02:00 host thessley-pam[3]: denied by 'My phone' (c_0123456789abcdef, no fingerprint) for {USER} (sudo, /dev/pts/1)",
            "2026-10-17T01:17:00+02:00 host kernel: unrelated",
        ]
        self.app.journal = lambda: lines
        self.login()
        _, body = self.b.get("/log")
        self.assertIn("Approved by My phone", body)
        self.assertIn("Denied by My phone", body)
        self.assertNotIn("somebody-else", body)
        self.admin = True
        _, everyone = self.b.get("/log?all=1")
        self.assertIn("somebody-else", everyone)

    def test_parse_activity(self):
        ok = web.parse_activity("2026-10-17T01:14:10+02:00 h thessley-pam[9]: pass granted to windows (sshd, from 192.168.1.190, 4 h)", None)
        self.assertEqual(ok, ("2026-10-17 01:14:10", "Pass granted to windows from 192.168.1.190 for 4 h"))
        self.assertIsNone(web.parse_activity("garbage", None))
        self.assertIsNone(web.parse_activity("2026-10-17T01:14:10+02:00 h thessley-pam[9]: timeout for bob (sshd, ssh)", "alice"))

    def test_certificate_is_kept_between_runs(self):
        cert, key = os.path.join(self.tmp.name, "again.pem"), os.path.join(self.tmp.name, "again.key")
        first = web.ensure_cert(cert, key, ["127.0.0.1"])
        self.assertEqual(web.ensure_cert(cert, key, ["127.0.0.1"]), first)
        self.assertEqual(os.stat(key).st_mode & 0o777, 0o600)


class KeyDetailsTest(WebBase):
    """What the page says about each key."""

    @staticmethod
    def fake_android_chain(key_level: int, attestation_level: int) -> list:
        import base64
        import datetime
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Android Keystore Key")])
        # KeyDescription: SEQUENCE { attestationVersion 4, attestationSecurityLevel, keymasterVersion 4, keymasterSecurityLevel }
        raw = bytes([0x30, 0x0C, 0x02, 0x01, 0x04, 0x0A, 0x01, attestation_level, 0x02, 0x01, 0x04, 0x0A, 0x01, key_level])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(1).not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=30))
                .add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier(web.ATTESTATION_OID), raw), critical=False)
                .sign(key, hashes.SHA256()))
        return [base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()]

    def keys_body(self):
        self.login()
        return self.b.get("/keys")[1]

    def test_an_app_key_says_what_it_is_and_shows_its_fingerprint(self):
        body = self.keys_body()
        self.assertIn("Details", body)
        self.assertIn("An app key", body)
        self.assertIn("ECDSA on secp256r1", body)
        self.assertRegex(body, r"[0-9a-f]{4}(:[0-9a-f]{4}){7}…")

    def test_a_phone_key_shows_where_the_key_lives(self):
        store.add_device(USER, FakePhone().spki, "Strong phone", self.fake_android_chain(key_level=2, attestation_level=1))
        body = self.keys_body()
        self.assertIn("A phone key (Android Keystore)", body)
        self.assertIn("StrongBox (separate secure chip)", body)
        self.assertIn("Trusted environment (TEE)", body)
        self.assertIn("does not check them against a root of trust", body)  # said plainly: stored, not verified

    def test_a_tpm_key_proven_at_enrolment_says_so_with_the_maker(self):
        store.add_device(USER, FakePhone().spki, "Desktop in a TPM", [],
                         {"level": "tpm", "maker": "INTC", "model": "ADL", "checked_at": 1760000000})
        body = self.keys_body()
        self.assertIn("held in a TPM chip, proven at enrolment", body)
        self.assertIn("Verified by this computer", body)
        self.assertIn("INTC ADL", body)
        self.assertIn("revocation lists are not checked", body)  # said plainly: what the proof does not cover

    def test_a_tpm_claim_that_did_not_verify_says_why(self):
        store.add_device(USER, FakePhone().spki, "Doubtful desktop", [],
                         {"level": "unverified", "reason": "certified name does not match the key"})
        body = self.keys_body()
        self.assertIn("could not verify it: certified name does not match the key", body)

    def test_an_unreadable_chain_does_not_break_the_page(self):
        store.add_device(USER, FakePhone().spki, "Odd phone", ["not base64 der"])
        body = self.keys_body()
        self.assertIn("could not be read", body)
        self.assertIn("Odd phone", body)

    def test_use_count_and_passes_come_from_the_log_and_the_pass_store(self):
        cred = self.device["credential_id"]
        self.app.journal = lambda: [
            f"2026-10-17T01:14:10+02:00 h thessley-pam[1]: approved by 'My phone' ({cred}) from 192.168.1.5 for {USER} (sshd, ssh)",
            f"2026-10-17T02:00:00+02:00 h thessley-pam[2]: approved by 'My phone' ({cred}) from 192.168.1.9 for {USER} (sudo, /dev/pts/1)",
        ]
        grants.add(USER, "sshd", "192.168.1.5", 4, cred)
        body = self.keys_body()
        self.assertIn("2, the last on 2026-10-17 02:00:00 from 192.168.1.9", body)
        self.assertIn("sshd from 192.168.1.5", body)

    def test_the_der_reader_refuses_garbage(self):
        for bad in (b"", b"\x30", b"\x31\x00", b"\x30\x05\x02"):
            with self.assertRaises((ValueError, IndexError)):
                web.parse_key_description(bad)


class SettingsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        store.BASE = os.path.join(self.tmp.name, "etc")
        store.USERS = os.path.join(store.BASE, "users")

    def test_defaults_and_limits(self):
        st = grants.web_settings()
        self.assertEqual((st["enabled"], st["listen"], st["port"], st["session_minutes"]), (False, "", 47820, 15))
        grants.set_web(enabled=True, port=70000, session_minutes=0)
        st = grants.web_settings()
        self.assertEqual((st["enabled"], st["port"], st["session_minutes"]), (True, 65535, 1))
        with self.assertRaises(ValueError):
            grants.set_web(nonsense=1)


if __name__ == "__main__":
    unittest.main()
