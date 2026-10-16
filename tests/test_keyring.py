"""Keyring unlock: password check, TPM sealing and the helper PAM calls. No root, no PAM.

Everything that needs a TPM runs only when TPM2TOOLS_TCTI points at a software TPM, e.g.

    swtpm socket --tpm2 --tpmstate dir=/tmp/x --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear &
    TPM2TOOLS_TCTI=swtpm:host=127.0.0.1,port=2321 python3 -I tests/test_keyring.py

(Never point it at the real TPM: one test deliberately changes PCR 7.)
"""

import ctypes
import io
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from thessley_pam import keyring  # noqa: E402

USER = os.environ.get("USER") or "ubuntu"
SOFT_TPM = os.environ.get("TPM2TOOLS_TCTI", "").startswith("swtpm:")


def sha512_hash(password: str, salt: str = "saltsalt") -> str:
    libcrypt = ctypes.CDLL("libcrypt.so.1")
    libcrypt.crypt.restype = ctypes.c_char_p
    libcrypt.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    return libcrypt.crypt(password.encode(), f"$6${salt}$".encode()).decode()


class Out(io.StringIO):
    def __init__(self, tty=False):
        super().__init__()
        self._tty = tty

    def isatty(self):
        return self._tty


class CheckPasswordTest(unittest.TestCase):
    def shadow(self, entry):
        f = tempfile.NamedTemporaryFile("w", delete=False)
        f.write(f"root:!:19000:0:99999:7:::\n{USER}:{entry}:19000:0:99999:7:::\n")
        f.close()
        self.addCleanup(os.unlink, f.name)
        return f.name

    def test_right_and_wrong(self):
        sh = self.shadow(sha512_hash("correct horse 9"))
        self.assertTrue(keyring.check_password(USER, "correct horse 9", sh))
        self.assertFalse(keyring.check_password(USER, "correct horse 8", sh))
        self.assertFalse(keyring.check_password(USER, "", sh))

    def test_unicode_password(self):
        sh = self.shadow(sha512_hash("pässwörd ✓"))
        self.assertTrue(keyring.check_password(USER, "pässwörd ✓", sh))

    def test_locked_and_passwordless_accounts_never_match(self):
        for entry in ("!", "*", "!$6$x$y", ""):
            self.assertFalse(keyring.check_password(USER, "anything", self.shadow(entry)), entry)

    def test_unknown_user(self):
        self.assertFalse(keyring.check_password("nobody-here", "x", self.shadow(sha512_hash("x"))))


class HelperRefusalTest(unittest.TestCase):
    """Whatever goes wrong, nothing is written to stdout: PAM would take it for the password."""

    def run_helper(self, argv, **kw):
        out = kw.pop("out", None) or Out()
        rc = keyring.helper_main(argv, out=out, **kw)
        return rc, out.getvalue()

    def test_wrong_arguments(self):
        for argv in ([], ["--keyring"], ["--other", USER], ["--keyring", USER, "extra"]):
            self.assertEqual(self.run_helper(argv, euid=0), (1, ""), argv)

    def test_not_root(self):
        self.assertEqual(self.run_helper(["--keyring", USER], euid=1000), (1, ""))

    def test_unknown_user(self):
        self.assertEqual(self.run_helper(["--keyring", "no-such-user-x"], euid=0, phones=lambda u: [1]), (1, ""))

    def test_user_without_a_phone(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, f"{USER}.pub"), "w").close()
            open(os.path.join(d, f"{USER}.priv"), "w").close()
            self.assertEqual(self.run_helper(["--keyring", USER], euid=0, base=d, phones=lambda u: []), (1, ""))

    def test_nothing_sealed(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(self.run_helper(["--keyring", USER], euid=0, base=d, phones=lambda u: [1]), (1, ""))

    def test_never_to_a_terminal(self):
        with tempfile.TemporaryDirectory() as d:
            rc, text = self.run_helper(["--keyring", USER], euid=0, base=d, phones=lambda u: [1], out=Out(tty=True))
            self.assertEqual((rc, text), (1, ""))


@unittest.skipUnless(SOFT_TPM, "needs a software TPM (see the module docstring)")
class SealingTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        keyring._flush_transient()

    def test_roundtrip_and_files_are_private(self):
        keyring.seal(USER, "pässwörd ✓ 123", base=self.tmp.name)
        self.assertEqual(keyring.unseal(USER, base=self.tmp.name), "pässwörd ✓ 123")
        for ext in ("pub", "priv"):
            mode = os.stat(os.path.join(self.tmp.name, f"{USER}.{ext}")).st_mode & 0o777
            self.assertEqual(mode, 0o600)
        for ext in ("pub", "priv"):  # the password is not lying around in the sealed files
            with open(os.path.join(self.tmp.name, f"{USER}.{ext}"), "rb") as fh:
                self.assertNotIn(b"ssw", fh.read())

    def test_sealing_again_replaces_the_old_password(self):
        keyring.seal(USER, "first-password", base=self.tmp.name)
        keyring.seal(USER, "second-password", base=self.tmp.name)
        self.assertEqual(keyring.unseal(USER, base=self.tmp.name), "second-password")

    def test_helper_prints_exactly_the_password(self):
        keyring.seal(USER, "Hunter2-xyz", base=self.tmp.name)
        out = Out()
        rc = keyring.helper_main(["--keyring", USER], euid=0, out=out, base=self.tmp.name, phones=lambda u: [1])
        self.assertEqual((rc, out.getvalue()), (0, "Hunter2-xyz"))

    def test_forget(self):
        keyring.seal(USER, "gone-soon-1", base=self.tmp.name)
        self.assertTrue(keyring.is_linked(USER, self.tmp.name))
        self.assertTrue(keyring.forget(USER, self.tmp.name))
        self.assertFalse(keyring.is_linked(USER, self.tmp.name))
        with self.assertRaises(keyring.KeyringError):
            keyring.unseal(USER, base=self.tmp.name)

    def test_refused_after_the_platform_state_changes(self):
        keyring.seal(USER, "bound-to-pcr7", base=self.tmp.name)
        self.assertEqual(keyring.unseal(USER, base=self.tmp.name), "bound-to-pcr7")
        subprocess.run(["tpm2_pcrextend", "7:sha256=" + "ab" * 32], check=True, capture_output=True)
        keyring._flush_transient()
        with self.assertRaises(keyring.KeyringError):
            keyring.unseal(USER, base=self.tmp.name)
        out = Out()
        rc = keyring.helper_main(["--keyring", USER], euid=0, out=out, base=self.tmp.name, phones=lambda u: [1])
        self.assertEqual((rc, out.getvalue()), (1, ""))  # PAM gets nothing: the keyring just stays locked
        keyring.seal(USER, "bound-to-pcr7", base=self.tmp.name)  # linking again under the new state works
        self.assertEqual(keyring.unseal(USER, base=self.tmp.name), "bound-to-pcr7")


if __name__ == "__main__":
    unittest.main()
