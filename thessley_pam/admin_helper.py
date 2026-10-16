"""The root side of the Thessley Login admin window (thessley-pam-admin).

The window runs as the ordinary user and reaches this through pkexec, so one polkit prompt covers it:

    pkexec /usr/local/lib/thessley-pam/admin-helper state
    pkexec /usr/local/lib/thessley-pam/admin-helper remove-phone CREDENTIAL_ID
    pkexec /usr/local/lib/thessley-pam/admin-helper keyring-forget

It only ever acts on the account of the person who asked (PKEXEC_UID), never on another user, and it prints one
JSON object on stdout. It never prints or logs a password. The sealed keyring password is not opened here
except to find out whether it still can be.
"""

import json
import os
import pwd
import re
import sys

from . import keyring, store

CREDENTIAL = re.compile(r"^c_[0-9a-f]{16}$")
SUDOERS_DIR = "/etc/sudoers.d"


def _caller(env) -> str:
    """The account that asked: pkexec sets PKEXEC_UID. (THESSLEY_ADMIN_USER is for tests run as root directly.)"""
    uid = env.get("PKEXEC_UID")
    if uid is not None:
        return pwd.getpwuid(int(uid)).pw_name
    name = env.get("THESSLEY_ADMIN_USER", "")
    if name:
        pwd.getpwnam(name)
        return name
    raise PermissionError("not started through pkexec")


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


def state(username: str) -> dict:
    phones = [
        {"credential_id": d["credential_id"], "label": d.get("label", ""), "enrolled_at": d.get("enrolled_at"),
         "last_used": d.get("last_used")}
        for d in store.devices(username)
    ]
    return {"user": username, "phones": phones, "keyring": keyring_state(username),
            "passwordless_sudo": passwordless_sudo(username)}


def main(argv: list[str], env=None) -> int:
    env = os.environ if env is None else env
    try:
        user = _caller(env)
        if argv[:1] == ["state"] and len(argv) == 1:
            out = state(user)
        elif argv[:1] == ["remove-phone"] and len(argv) == 2 and CREDENTIAL.match(argv[1]):
            out = {"removed": store.remove_device(user, argv[1])}
        elif argv[:1] == ["keyring-forget"] and len(argv) == 1:
            out = {"forgotten": keyring.forget(user)}
        else:
            print(json.dumps({"error": "bad request"}))
            return 2
    except (PermissionError, KeyError, ValueError, OSError) as exc:
        print(json.dumps({"error": str(exc)[:200]}))
        return 1
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
