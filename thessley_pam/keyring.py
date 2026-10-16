"""Unlock the GNOME login keyring after a phone login.

A normal login unlocks the keyring because the person typed the password and pam_gnome_keyring uses it. A QR
login types nothing, so the keyring would stay locked. This module keeps the user's login password sealed in
the computer's TPM, and gives it back to PAM only after the phone has approved the login.

    sudo thessley-pam keyring-link      ask for the password once, check it, seal it in the TPM
    sudo thessley-pam keyring-forget    delete the sealed copy
    sudo thessley-pam keyring-status

Why a TPM and not a file: a stolen disk (or a backup) must not give up the password. The sealed blob can only be
opened by this computer's TPM, and only while the platform state in PCR 7 (Secure Boot configuration) is what it
was when the password was sealed. If that changes (firmware or Secure Boot key update), unsealing fails and the
login simply works without unlocking the keyring: the person is asked for the keyring password later. Run
keyring-link again to refresh it.

The password is released only by pam-keyring-helper, which is called by pam_thessley_authtok.so after the phone
step of /etc/pam.d/gdm-thessley, runs as root, refuses to write to a terminal, and refuses users with no enrolled
phone. Nothing here ever prints or logs the password.

Layout (root only):
    /etc/thessley-pam/keyring/<user>.pub  <user>.priv  the sealed object (public and encrypted private part)
"""

import ctypes
import hmac
import os
import pwd
import shutil
import subprocess
import sys
import syslog
import tempfile

from . import store

KEYRING_DIR = os.path.join(store.BASE, "keyring")
SHADOW = "/etc/shadow"
PCRS = "sha256:7"
TPM_TIMEOUT = 20
MAX_PASSWORD = 256


class KeyringError(Exception):
    pass


def _log(msg: str, warn: bool = False) -> None:
    syslog.openlog("thessley-pam", syslog.LOG_PID, syslog.LOG_AUTHPRIV)
    syslog.syslog(syslog.LOG_WARNING if warn else syslog.LOG_INFO, msg)


def _paths(username: str, base: str | None = None) -> tuple[str, str]:
    pwd.getpwnam(username)  # KeyError for an unknown account, and no path tricks in the name
    d = base or KEYRING_DIR
    return os.path.join(d, f"{username}.pub"), os.path.join(d, f"{username}.priv")


# ---- checking the password ------------------------------------------------------------------------------------

def check_password(username: str, password: str, shadow: str = SHADOW) -> bool:
    """True if `password` is the account's current login password (needs to read /etc/shadow, so root)."""
    entry = None
    with open(shadow) as f:
        for line in f:
            parts = line.rstrip("\n").split(":")
            if parts[0] == username and len(parts) > 1:
                entry = parts[1]
                break
    if not entry or entry[0] in "!*":  # no such account, locked, or no password
        return False
    libcrypt = ctypes.CDLL("libcrypt.so.1")
    libcrypt.crypt.restype = ctypes.c_char_p
    libcrypt.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    got = libcrypt.crypt(password.encode(), entry.encode())
    return bool(got) and hmac.compare_digest(got.decode(), entry)


# ---- sealing in the TPM (tpm2-tools) ----------------------------------------------------------------------------

def _tpm(args: list[str], stdin: bytes | None = None) -> bytes:
    try:
        out = subprocess.run(args, input=stdin, capture_output=True, timeout=TPM_TIMEOUT, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise KeyringError(f"{args[0]}: {exc}") from exc
    if out.returncode != 0:
        raise KeyringError(f"{args[0]} failed: {out.stderr.decode(errors='replace').strip()[:300]}")
    return out.stdout


def _flush_transient(sessions: bool = True) -> None:
    """A TPM without a resource manager (a software TPM in tests) keeps objects loaded after a tool exits and has
    only a few slots. Through /dev/tpmrm0 this finds nothing to do."""
    args = ["tpm2_flushcontext", "-t"] + (["-l", "-s"] if sessions else [])
    subprocess.run(args, capture_output=True, timeout=TPM_TIMEOUT, check=False)


class _Work:
    """A private scratch directory on tmpfs (/run) for TPM context files; none of them holds a secret."""

    def __enter__(self):
        _flush_transient()
        parent = "/run" if os.path.isdir("/run") and os.access("/run", os.W_OK) else None
        self.dir = tempfile.mkdtemp(prefix="thessley-kr.", dir=parent)
        os.chmod(self.dir, 0o700)
        return self.dir

    def __exit__(self, *exc):
        _flush_transient()
        shutil.rmtree(self.dir, ignore_errors=True)


def _primary(work: str) -> str:
    ctx = os.path.join(work, "primary.ctx")
    _tpm(["tpm2_createprimary", "-C", "o", "-G", "ecc", "-g", "sha256", "-c", ctx])
    return ctx


def seal(username: str, password: str, base: str | None = None) -> None:
    """Seal `password` to this TPM and to the current PCR 7. Replaces any earlier copy."""
    data = password.encode()
    if not data or len(data) > MAX_PASSWORD:
        raise KeyringError("The password is empty or too long.")
    pub, priv = _paths(username, base)
    os.makedirs(os.path.dirname(pub), mode=0o700, exist_ok=True)
    os.chmod(os.path.dirname(pub), 0o700)
    with _Work() as work:
        primary = _primary(work)
        policy = os.path.join(work, "policy.dat")
        _tpm(["tpm2_createpolicy", "--policy-pcr", "-l", PCRS, "-L", policy])
        tmp_pub, tmp_priv = os.path.join(work, "k.pub"), os.path.join(work, "k.priv")
        # userwithauth is deliberately NOT set: otherwise the empty password would open the object and the PCR
        # policy would be decoration.
        _tpm(["tpm2_create", "-C", primary, "-L", policy, "-i-", "-u", tmp_pub, "-r", tmp_priv,
              "-a", "fixedtpm|fixedparent|noda|adminwithpolicy"], stdin=data)
        for src, dst in ((tmp_pub, pub), (tmp_priv, priv)):
            shutil.copyfile(src, dst + ".new")
            os.chmod(dst + ".new", 0o600)
            os.replace(dst + ".new", dst)


def unseal(username: str, base: str | None = None) -> str:
    """The sealed password, or KeyringError (no copy, other TPM, PCR 7 changed, TPM busy...)."""
    pub, priv = _paths(username, base)
    if not (os.path.exists(pub) and os.path.exists(priv)):
        raise KeyringError("no sealed password for this user")
    with _Work() as work:
        primary = _primary(work)
        ctx = os.path.join(work, "k.ctx")
        _tpm(["tpm2_load", "-C", primary, "-u", pub, "-r", priv, "-c", ctx])
        _flush_transient(sessions=False)  # the saved context files are all that is needed from here on
        session = os.path.join(work, "session.ctx")
        _tpm(["tpm2_startauthsession", "--policy-session", "-S", session])
        try:
            _tpm(["tpm2_policypcr", "-S", session, "-l", PCRS])
            _flush_transient(sessions=False)  # keep the policy session itself
            data = _tpm(["tpm2_unseal", "-c", ctx, "-p", f"session:{session}"])
        finally:
            subprocess.run(["tpm2_flushcontext", session], capture_output=True, timeout=TPM_TIMEOUT, check=False)
    if not data or len(data) > MAX_PASSWORD:
        raise KeyringError("unexpected sealed data")
    return data.decode()


def forget(username: str, base: str | None = None) -> bool:
    pub, priv = _paths(username, base)
    gone = False
    for p in (pub, priv):
        if os.path.exists(p):
            os.unlink(p)
            gone = True
    return gone


def is_linked(username: str, base: str | None = None) -> bool:
    pub, priv = _paths(username, base)
    return os.path.exists(pub) and os.path.exists(priv)


# ---- the helper PAM calls ---------------------------------------------------------------------------------------

def helper_main(argv: list[str], *, euid: int | None = None, out=None, base: str | None = None, phones=None) -> int:
    """pam-keyring-helper --keyring USER: write the user's sealed password to stdout (no newline) and exit 0, or
    write nothing and exit 1. Never an error message on stdout: PAM reads whatever is there as the password."""
    out = out or sys.stdout
    euid = os.geteuid() if euid is None else euid
    if len(argv) != 2 or argv[0] != "--keyring":
        return 1
    username = argv[1]
    if euid != 0:
        return 1
    try:
        if out.isatty():
            _log("keyring: refusing to write the password to a terminal", warn=True)
            return 1
        if not (phones if phones is not None else store.devices)(username):
            return 1  # only users who set up phone login
        if not is_linked(username, base):
            return 1
        password = unseal(username, base)
    except (KeyError, KeyringError, OSError) as exc:
        _log(f"keyring: not unlocking for {username!r}: {exc}", warn=True)
        return 1
    out.write(password)
    out.flush()
    _log(f"keyring: password released for {username!r}")
    return 0
