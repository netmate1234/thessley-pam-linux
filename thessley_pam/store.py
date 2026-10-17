"""Enrolled phones, one root-only JSON file per Ubuntu user.

    /etc/thessley-pam/            0700 root
    /etc/thessley-pam/users/      0700 root
    /etc/thessley-pam/users/<user>.json   0600 root

Only public keys live here, but the files decide who may log in, so nobody but root may read or change them.
"""

import json
import os
import pwd
import secrets
import tempfile
import time

BASE = "/etc/thessley-pam"
USERS = os.path.join(BASE, "users")
# World-readable list of user names that have at least one phone, one per line. The GNOME Shell extension runs
# as the gdm user (login screen) or as the user (lock screen) and can't read BASE; it uses this to decide
# whether to offer the QR code at all. Holds names only, no keys.
ENROLLED = "/etc/thessley-pam-enrolled"


def _check_user(username: str) -> None:
    pwd.getpwnam(username)  # KeyError if no such account; also rules out path tricks in the name


def _path(username: str) -> str:
    _check_user(username)
    return os.path.join(USERS, f"{username}.json")


def show_link() -> bool:
    """Print each request's link as text, under or above the QR code? On unless switched off (thessley-pam show-link
    off): a person who cannot scan (an ssh app on the phone, a remote desktop) needs the text."""
    return not os.path.exists(os.path.join(BASE, "hide-link"))


def ensure_dirs() -> None:
    for d in (BASE, USERS):
        os.makedirs(d, mode=0o700, exist_ok=True)
        os.chmod(d, 0o700)


def load(username: str) -> dict:
    try:
        with open(_path(username)) as f:
            data = json.load(f)
    except FileNotFoundError:
        return {"version": 1, "username": username, "devices": []}
    data.setdefault("devices", [])
    return data


def save(username: str, data: dict) -> None:
    ensure_dirs()
    path = _path(username)
    fd, tmp = tempfile.mkstemp(dir=USERS, prefix=f".{username}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    write_enrolled_list()


def write_enrolled_list() -> None:
    names = []
    for entry in sorted(os.listdir(USERS)):
        if not entry.endswith(".json") or entry.startswith("."):
            continue
        with open(os.path.join(USERS, entry)) as f:
            if any(not d.get("disabled") for d in json.load(f).get("devices", [])):
                names.append(entry[:-5])
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(ENROLLED), prefix=".thessley-pam-enrolled.")
    with os.fdopen(fd, "w") as f:
        f.write("".join(n + "\n" for n in names))
    os.chmod(tmp, 0o644)
    os.replace(tmp, ENROLLED)


def devices(username: str) -> list[dict]:
    """Every enrolled phone, including disabled ones (for listing and managing)."""
    return load(username)["devices"]


def active_devices(username: str) -> list[dict]:
    """The phones that may approve things: not disabled. A user whose phones are all disabled is treated as having none."""
    return [d for d in devices(username) if not d.get("disabled")]


def set_disabled(username: str, credential_id: str, disabled: bool) -> bool:
    """Switch a phone off (or on) without forgetting its key. False if there is no such phone."""
    data = load(username)
    for d in data["devices"]:
        if d["credential_id"] == credential_id:
            if disabled:
                d["disabled"] = True
            else:
                d.pop("disabled", None)
            save(username, data)
            if disabled:
                _end_passes(username, credential_id)
            return True
    return False


def rename_device(username: str, credential_id: str, label: str) -> bool:
    """Change the name a phone is listed under. False if there is no such phone."""
    data = load(username)
    for d in data["devices"]:
        if d["credential_id"] == credential_id:
            d["label"] = label
            save(username, data)
            return True
    return False


def all_users() -> list[str]:
    """Every account that has a phone list (enrolled now or earlier), sorted."""
    try:
        return sorted(n[:-5] for n in os.listdir(USERS) if n.endswith(".json") and not n.startswith("."))
    except OSError:
        return []


def add_device(username: str, public_key: str, label: str, attestation_chain: list[str],
               attestation: dict | None = None) -> dict:
    """Store one phone or app. `attestation` is what this computer itself checked at enrolment (TPM proof), if anything:
    {"level": "tpm", "maker": ..., "model": ..., "checked_at": ...} or {"level": "unverified", "reason": ...}."""
    data = load(username)
    device = {
        "credential_id": "c_" + secrets.token_hex(8),
        "public_key": public_key,
        "label": label,
        "enrolled_at": int(time.time()),
        "last_used": None,
        "attestation_chain": attestation_chain,
    }
    if attestation:
        device["attestation"] = attestation
    data["devices"].append(device)
    save(username, data)
    return device


def touch(username: str, credential_id: str) -> None:
    data = load(username)
    for d in data["devices"]:
        if d["credential_id"] == credential_id:
            d["last_used"] = int(time.time())
            save(username, data)
            return


def _end_passes(username: str, credential_id: str) -> None:
    """A phone that is removed or switched off takes the passes it granted with it."""
    from . import grants
    try:
        grants.revoke_credential(username, credential_id)
    except OSError:
        pass


def remove_device(username: str, credential_id: str) -> bool:
    data = load(username)
    before = len(data["devices"])
    data["devices"] = [d for d in data["devices"] if d["credential_id"] != credential_id]
    if len(data["devices"]) == before:
        return False
    save(username, data)
    _end_passes(username, credential_id)
    return True
