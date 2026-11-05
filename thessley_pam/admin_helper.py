"""The root side of the Thessley Login admin window (thessley-pam-admin).

The window runs as the ordinary user and reaches this through pkexec, so one polkit prompt covers it:

    pkexec /usr/local/lib/thessley-pam/admin-helper state
    pkexec /usr/local/lib/thessley-pam/admin-helper remove-phone CREDENTIAL_ID
    pkexec /usr/local/lib/thessley-pam/admin-helper keyring-forget
    pkexec /usr/local/lib/thessley-pam/admin-helper set-phone CREDENTIAL_ID on|off
    pkexec /usr/local/lib/thessley-pam/admin-helper set-feature login-qr|sudo-phone|keyring-unlock on|off

It only ever acts on the account of the person who asked (PKEXEC_UID), never on another user, and it prints one
JSON object on stdout. It never prints or logs a password. The sealed keyring password is not opened here
except to find out whether it still can be.
"""

import json
import os
import pwd
import re
import subprocess
import sys
import tempfile

from . import keyring, store

CREDENTIAL = re.compile(r"^c_[0-9a-f]{16}$")
SUDOERS_DIR = "/etc/sudoers.d"
PAM_DIR = "/etc/pam.d"
GREETER = "/etc/gdm3/greeter.dconf-defaults"
UUID = "thessley-passkey-login@eagleeye-intelligence.com"
OFF_MARK = "#thessley-disabled# "  # in front of a PAM line this program switched off; nothing else uses it


def _caller(env) -> str:
    """The account that asked: pkexec sets PKEXEC_UID, sudo sets SUDO_UID (both are set by the tool itself, not by
    the caller). THESSLEY_ADMIN_USER is for tests run as root directly."""
    uid = env.get("PKEXEC_UID") or env.get("SUDO_UID")
    if uid is not None:
        return pwd.getpwuid(int(uid)).pw_name
    name = env.get("THESSLEY_ADMIN_USER", "")
    if name:
        pwd.getpwnam(name)
        return name
    raise PermissionError("not started through pkexec or sudo")


def passwordless_sudo(username: str, sudoers_dir: str = SUDOERS_DIR) -> bool:
    """True if a sudoers file gives this account (or ALL users) NOPASSWD, so sudo never asks for anything."""
    try:
        names = sorted(os.listdir(sudoers_dir))
    except OSError:
        return False
    for name in names:
        if name.startswith(".") or "~" in name:
            continue
        try:
            with open(os.path.join(sudoers_dir, name)) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("#") or "NOPASSWD" not in line:
                        continue
                    who = line.split()[0]
                    if who in (username, "ALL", f"%{username}"):
                        return True
        except OSError:
            continue
    return False


def keyring_state(username: str) -> dict:
    if not keyring.is_linked(username):
        return {"sealed": False, "readable": False, "error": ""}
    try:
        keyring.unseal(username)
    except keyring.KeyringError as exc:
        return {"sealed": True, "readable": False, "error": str(exc)[-200:]}
    return {"sealed": True, "readable": True, "error": ""}


# ---- the switches -----------------------------------------------------------------------------------------------
#
# Each feature is one PAM line (or one greeter setting) that this program can switch off by putting OFF_MARK in
# front of it, and back on by taking the mark away. Nothing else is edited, a copy of the original is kept the
# first time (<file>.bak-thessley-admin), the new text is checked before it replaces the file, and the file is
# replaced in one step with its owner and mode unchanged. A half-written PAM file is how people lock themselves
# out, so this is deliberately strict.

FEATURES = {
    # name: (file, text the line must contain, text the file must still contain afterwards)
    "sudo-phone": ("sudo", "pam-helper", "common-auth"),
    "keyring-unlock": ("gdm-thessley", "pam_thessley_authtok.so", "pam_exec.so"),
}
QR_ONLY_LINE = "auth    requisite       pam_deny.so # THESSLEY_QR_ONLY"
QR_ONLY_NEEDLE = "THESSLEY_QR_ONLY"


def _rewrite(path: str, text: str) -> None:
    backup = path + ".bak-thessley-admin"
    st = os.stat(path)
    if not os.path.exists(backup):
        with open(path) as src, open(backup, "w") as dst:
            dst.write(src.read())
        os.chmod(backup, 0o600)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".thessley-admin.")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chown(tmp, st.st_uid, st.st_gid)
        os.chmod(tmp, st.st_mode & 0o7777)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def _pam_line(line: str, needle: str) -> bool:
    """The auth line for this feature, in either state."""
    body = line[len(OFF_MARK):] if line.startswith(OFF_MARK) else line
    parts = body.split()
    return len(parts) >= 3 and parts[0] == "auth" and needle in body and not body.lstrip().startswith("#")


def pam_feature_state(name: str, pam_dir: str = PAM_DIR) -> str:
    """'on', 'off' or 'absent' (the file or the line is not there)."""
    filename, needle, _ = FEATURES[name]
    try:
        with open(os.path.join(pam_dir, filename)) as f:
            lines = f.read().splitlines()
    except OSError:
        return "absent"
    states = {("off" if ln.startswith(OFF_MARK) else "on") for ln in lines if _pam_line(ln, needle)}
    return "off" if states == {"off"} else "on" if "on" in states else "absent"


def set_pam_feature(name: str, on: bool, pam_dir: str = PAM_DIR) -> str:
    filename, needle, must_keep = FEATURES[name]
    path = os.path.join(pam_dir, filename)
    with open(path) as f:
        original = f.read()
    out, changed = [], 0
    for ln in original.splitlines():
        if _pam_line(ln, needle):
            if on and ln.startswith(OFF_MARK):
                ln, changed = ln[len(OFF_MARK):], changed + 1
            elif not on and not ln.startswith(OFF_MARK):
                ln, changed = OFF_MARK + ln, changed + 1
        out.append(ln)
    if not changed:
        return pam_feature_state(name, pam_dir)
    text = "\n".join(out) + ("\n" if original.endswith("\n") else "")
    live = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    if not any(must_keep in ln for ln in live):  # never write a file that lost its essential line
        raise ValueError(f"refusing to edit {filename}: it would no longer contain {must_keep}")
    _rewrite(path, text)
    return pam_feature_state(name, pam_dir)


def login_qr_only_state(pam_dir: str = PAM_DIR) -> str:
    """Whether GDM password authentication is blocked to make Thessley QR the only password path."""
    try:
        with open(os.path.join(pam_dir, "gdm-password"), encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError:
        return "absent"
    active = any(_pam_line(line, QR_ONLY_NEEDLE) and not line.startswith(OFF_MARK) for line in lines)
    return "on" if active else "off"


def set_login_qr_only(on: bool, pam_dir: str = PAM_DIR, greeter: str = GREETER) -> str:
    """Block/unblock GDM password auth, leaving the independent Thessley QR PAM service available.

    The deny rule is placed immediately before common-auth and managed reversibly. Refuse unknown PAM layouts,
    and require the QR greeter extension to be enabled before turning off the password route.
    """
    path = os.path.join(pam_dir, "gdm-password")
    with open(path, encoding="utf-8") as f:
        original = f.read()
    lines = original.splitlines()
    managed = [i for i, line in enumerate(lines) if _pam_line(line, QR_ONLY_NEEDLE)]
    if len(managed) > 1:
        raise ValueError("refusing to edit gdm-password: multiple Thessley QR-only rules found")
    if not on and not managed:
        return "off"
    if on and login_qr_state(greeter) != "on":
        raise ValueError("enable the Thessley QR login screen before disabling password fallback")
    try:
        with open(os.path.join(pam_dir, "gdm-thessley"), encoding="utf-8") as f:
            phone_service = f.read().splitlines()
    except OSError as exc:
        raise ValueError("the Thessley phone login PAM service is not installed") from exc
    if not any(line.lstrip().startswith("auth") and "pam-helper" in line and "--login" in line
               and not line.lstrip().startswith("#") for line in phone_service):
        raise ValueError("the Thessley phone login PAM service is not enabled")
    common_auth = [i for i, line in enumerate(lines)
                   if line.strip() == "@include common-auth"]
    if on and not common_auth:
        raise ValueError("refusing to edit gdm-password: expected an @include common-auth line")

    if managed:
        i = managed[0]
        if on and lines[i].startswith(OFF_MARK):
            lines[i] = lines[i][len(OFF_MARK):]
        elif not on and not lines[i].startswith(OFF_MARK):
            lines[i] = OFF_MARK + lines[i]
        else:
            return "on" if on else "off"
    elif on:
        lines.insert(common_auth[0], QR_ONLY_LINE)

    text = "\n".join(lines) + ("\n" if original.endswith("\n") else "")
    live = [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if on and ("@include common-auth" not in live or not any(QR_ONLY_NEEDLE in line for line in live)):
        raise ValueError("refusing to edit gdm-password: resulting authentication stack failed validation")
    _rewrite(path, text)
    return login_qr_only_state(pam_dir)


def login_qr_state(greeter: str = GREETER) -> str:
    try:
        with open(greeter) as f:
            return "on" if UUID in f.read() else "off"
    except OSError:
        return "absent"


def set_login_qr(on: bool, greeter: str = GREETER,
                 regenerate=lambda: subprocess.run(["/usr/share/gdm/generate-config"], check=True),
                 pam_dir: str = PAM_DIR) -> str:
    """Show the QR code on the GNOME login screen (an entry in the greeter's dconf defaults) or hide it."""
    if not on and login_qr_only_state(pam_dir) == "on":
        raise ValueError("turn off QR-only login before hiding the Thessley QR screen")
    with open(greeter) as f:
        original = f.read()
    has = UUID in original
    if on == has:
        return "on" if has else "off"
    block = ("\n# Thessley Passkey: QR login on the login screen (install-login.sh)\n[org/gnome/shell]\n"
             f"enabled-extensions=['{UUID}']\n")
    if on:
        if re.search(r"^\[org/gnome/shell\]", original, re.M):
            raise ValueError("the greeter settings already have an [org/gnome/shell] section; add the extension by hand")
        text = original.rstrip("\n") + "\n" + block
    else:
        text = original.replace(block, "")
        if UUID in text:
            raise ValueError("the greeter settings were edited by hand; remove the extension line by hand")
    _rewrite(greeter, text)
    regenerate()
    return "on" if on else "off"


def features() -> dict:
    return {"login_qr": login_qr_state(), "sudo_phone": pam_feature_state("sudo-phone"),
            "keyring_unlock": pam_feature_state("keyring-unlock"),
            "login_qr_only": login_qr_only_state()}


def state(username: str) -> dict:
    phones = [
        {"credential_id": d["credential_id"], "label": d.get("label", ""), "enrolled_at": d.get("enrolled_at"),
         "last_used": d.get("last_used"), "disabled": bool(d.get("disabled"))}
        for d in store.devices(username)
    ]
    return {"user": username, "phones": phones, "keyring": keyring_state(username),
            "passwordless_sudo": passwordless_sudo(username), "features": features()}


def main(argv: list[str], env=None) -> int:
    env = os.environ if env is None else env
    try:
        user = _caller(env)
        if argv[:1] == ["state"] and len(argv) == 1:
            out = state(user)
        elif argv[:1] == ["remove-phone"] and len(argv) == 2 and CREDENTIAL.match(argv[1]):
            out = {"removed": store.remove_device(user, argv[1])}
        elif argv[:1] == ["set-phone"] and len(argv) == 3 and CREDENTIAL.match(argv[1]) and argv[2] in ("on", "off"):
            out = {"ok": store.set_disabled(user, argv[1], argv[2] == "off")}
        elif argv[:1] == ["set-feature"] and len(argv) == 3 and argv[1] in ("login-qr", "login-qr-only", *FEATURES) and argv[2] in ("on", "off"):
            on = argv[2] == "on"
            if argv[1] == "login-qr-only" and on and not store.active_devices(user):
                raise ValueError("enroll a Thessley phone for this account before disabling password fallback")
            out = {"state": (set_login_qr(on) if argv[1] == "login-qr" else
                             set_login_qr_only(on) if argv[1] == "login-qr-only" else
                             set_pam_feature(argv[1], on))}
        elif argv[:1] == ["keyring-forget"] and len(argv) == 1:
            out = {"forgotten": keyring.forget(user)}
        else:
            print(json.dumps({"error": "bad request"}))
            return 2
    except (PermissionError, KeyError, ValueError, OSError, subprocess.CalledProcessError) as exc:
        print(json.dumps({"error": str(exc)[:200]}))
        return 1
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
