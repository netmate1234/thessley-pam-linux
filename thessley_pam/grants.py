"""Phone passes: after one phone approval, the same user logging in to the same service from the same place needs
no new approval for a set number of hours.

Meant for ssh:  ssh key + phone once, then the ssh key alone for the next 4 hours.

    sudo thessley-pam grace --service sshd --hours 4      turn it on for a PAM service
    sudo thessley-pam passes                              who holds a pass right now
    sudo thessley-pam end-pass [--user NAME] [--service S] end passes at once

A pass is one entry in /run/thessley-pam/grants/<user>.json (root only, on tmpfs, so a reboot ends every pass):

    service      the PAM service it was granted for (sshd, ...); a pass for sshd never works for sudo
    rhost        where the login came from (PAM_RHOST, the client's address; "-" for a local login)
    credential   the phone that approved; if that phone is removed or switched off the pass stops working
    expires_at   fixed from the moment of the approval; using a pass does not extend it

What a pass does NOT know: which ssh key was used. sshd tells PAM nothing about the key during authentication, so
a pass is tied to the user, the service and the client's address, not to the key. Whoever holds a valid key for
this user and connects from the same address during the window is let through without the phone. That is the price
of the convenience; keep the window short and end passes (end-pass) when in doubt.
"""

import json
import os
import tempfile
import time

from . import store

RUN = "/run/thessley-pam"
GRANTS = os.path.join(RUN, "grants")
MAX_HOURS = 24.0
LOCAL = "-"


def _config_path() -> str:
    return os.path.join(store.BASE, "config.json")


def _load_config() -> dict:
    try:
        with open(_config_path()) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def grace_hours(service: str) -> float:
    """Hours a phone approval stays valid for this PAM service; 0 means every login asks (the default)."""
    try:
        hours = float(_load_config().get("grace", {}).get(service, 0))
    except (TypeError, ValueError, AttributeError):
        return 0.0
    return min(max(hours, 0.0), MAX_HOURS)


def requires_phone(service: str) -> bool:
    """True if a user with no enrolled (active) phone is refused for this service instead of passing through.
    Off by default, as it is for sudo (so nobody who never opted in is locked out); on for ssh, where the phone is
    the only second step and a missing phone would silently mean no second step at all."""
    try:
        return service in list(_load_config().get("require", []))
    except TypeError:
        return False


def set_require(service: str, on: bool) -> None:
    if not service or any(c in service for c in "/ \t\n\0") or service.startswith("."):
        raise ValueError("bad service name")
    store.ensure_dirs()
    data = _load_config()
    names = [n for n in data.get("require", []) if n != service]
    if on:
        names.append(service)
    if names:
        data["require"] = sorted(names)
    else:
        data.pop("require", None)
    _atomic_write(_config_path(), data, store.BASE)


def set_grace(service: str, hours: float) -> None:
    if not service or any(c in service for c in "/ \t\n\0") or service.startswith("."):
        raise ValueError("bad service name")
    hours = min(max(float(hours), 0.0), MAX_HOURS)
    store.ensure_dirs()
    data = _load_config()
    grace = data.setdefault("grace", {})
    if hours > 0:
        grace[service] = hours
    else:
        grace.pop(service, None)
    _atomic_write(_config_path(), data, store.BASE)


def _atomic_write(path: str, data, directory: str) -> None:
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp.")
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


def _ensure_dir() -> None:
    os.makedirs(GRANTS, mode=0o700, exist_ok=True)
    os.chmod(RUN, 0o700)
    os.chmod(GRANTS, 0o700)


def _path(username: str) -> str:
    store._check_user(username)  # KeyError for an unknown account; no path tricks in the name
    return os.path.join(GRANTS, f"{username}.json")


def _load(username: str) -> list[dict]:
    try:
        with open(_path(username)) as f:
            items = json.load(f)
        return [i for i in items if isinstance(i, dict)] if isinstance(items, list) else []
    except (OSError, ValueError):
        return []


def _save(username: str, items: list[dict]) -> None:
    _ensure_dir()
    path = _path(username)
    if not items:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        return
    _atomic_write(path, items, GRANTS)


def _live(items: list[dict], now: float) -> list[dict]:
    return [i for i in items if isinstance(i.get("expires_at"), (int, float)) and i["expires_at"] > now]


def valid(username: str, service: str, rhost: str, active_credentials, now: float | None = None) -> dict | None:
    """The pass that lets this login through, or None. `active_credentials`: credential ids of the user's phones
    that may still approve (a pass of a removed or switched-off phone is worthless)."""
    now = time.time() if now is None else now
    rhost = rhost or LOCAL
    for item in _live(_load(username), now):
        if item.get("service") == service and item.get("rhost") == rhost and item.get("credential") in set(active_credentials):
            return item
    return None


def add(username: str, service: str, rhost: str, hours: float, credential: str, now: float | None = None) -> dict:
    """Record an approval. An earlier pass for the same user, service and place is replaced."""
    now = time.time() if now is None else now
    rhost = rhost or LOCAL
    hours = min(max(float(hours), 0.0), MAX_HOURS)
    entry = {"service": service, "rhost": rhost, "credential": credential, "approved_at": int(now),
             "expires_at": int(now + hours * 3600)}
    items = [i for i in _live(_load(username), now) if not (i.get("service") == service and i.get("rhost") == rhost)]
    items.append(entry)
    _save(username, items)
    return entry


def all_passes(now: float | None = None) -> list[dict]:
    """Every live pass on this computer, with the user's name added."""
    now = time.time() if now is None else now
    out = []
    try:
        names = sorted(n[:-5] for n in os.listdir(GRANTS) if n.endswith(".json") and not n.startswith("."))
    except OSError:
        return out
    for name in names:
        try:
            out.extend({"user": name, **i} for i in _live(_load(name), now))
        except KeyError:  # account no longer exists
            continue
    return out


def revoke(username: str | None = None, service: str | None = None) -> int:
    """End passes (all of a user's, or one service's). Returns how many ended."""
    ended = 0
    users = [username] if username else sorted({p["user"] for p in all_passes()})
    for name in users:
        items = _load(name)
        keep = [i for i in items if service and i.get("service") != service]
        ended += len(items) - len(keep)
        _save(name, keep)
    return ended


def revoke_credential(username: str, credential: str) -> int:
    """End every pass that one phone approved (called when that phone is removed or switched off)."""
    items = _load(username)
    keep = [i for i in items if i.get("credential") != credential]
    if len(keep) != len(items):
        _save(username, keep)
    return len(items) - len(keep)


def remaining(entry: dict, now: float | None = None) -> str:
    seconds = max(0, int(entry["expires_at"] - (time.time() if now is None else now)))
    h, m = divmod(seconds // 60, 60)
    return f"{h} h {m:02d} min" if h else f"{m} min"
