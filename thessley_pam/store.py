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


def _check_user(username: str) -> None:
    pwd.getpwnam(username)  # KeyError if no such account; also rules out path tricks in the name


def _path(username: str) -> str:
    _check_user(username)
    return os.path.join(USERS, f"{username}.json")


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


def devices(username: str) -> list[dict]:
    return load(username)["devices"]


def add_device(username: str, public_key: str, label: str, attestation_chain: list[str]) -> dict:
    data = load(username)
    device = {
        "credential_id": "c_" + secrets.token_hex(8),
        "public_key": public_key,
        "label": label,
        "enrolled_at": int(time.time()),
        "last_used": None,
        "attestation_chain": attestation_chain,
    }
    data["devices"].append(device)
    save(username, data)
    return device


def remove_device(username: str, credential_id: str) -> bool:
    data = load(username)
    before = len(data["devices"])
    data["devices"] = [d for d in data["devices"] if d["credential_id"] != credential_id]
    if len(data["devices"]) == before:
        return False
    save(username, data)
    return True
