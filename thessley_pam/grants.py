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

import grp
import ipaddress
import json
import os
import pwd
import re
import stat
import subprocess
import tempfile
import time

from . import machine, store

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


NO_GRACE = ("openvpn", "thessley-vpn-download", "thessley-vpn-revoke")  # VPN access and certificate changes require fresh approval


def parse_ssh_allowed_ips(value: str | list[str] | tuple[str, ...]) -> list[str]:
    """Normalize a comma/space-separated set of SSH client IPs or CIDRs; empty means unrestricted."""
    if isinstance(value, str):
        entries = value.replace(",", " ").split()
    elif isinstance(value, (list, tuple)):
        entries = [str(item).strip() for item in value if str(item).strip()]
    else:
        raise ValueError("Enter IP addresses or CIDR networks, or leave the field empty for any IP.")
    if len(entries) > 64:
        raise ValueError("Enter no more than 64 IP addresses or networks.")
    result = []
    for entry in entries:
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid IP address or CIDR network: {entry}") from exc
        normalized = str(network)
        if normalized not in result:
            result.append(normalized)
    return result


def ssh_allowed_ips() -> list[str]:
    """Return the custom SSH source allowlist, if one is configured."""
    config = _load_config()
    if "ssh_allowed_ips" not in config:
        return []
    return parse_ssh_allowed_ips(config["ssh_allowed_ips"])


SSH_SOURCE_MODES = ("any", "local", "vpn", "custom")


def ssh_source_mode() -> str:
    """Return one source mode for older callers, or 'multiple' when the checkboxes combine modes."""
    modes = ssh_source_modes()
    return modes[0] if len(modes) == 1 else ("multiple" if modes else "invalid")


def ssh_source_modes() -> list[str]:
    """Return selected source modes, migrating the earlier single-mode and custom-list settings."""
    config = _load_config()
    selected = config.get("ssh_source_modes")
    if selected is not None:
        if (not isinstance(selected, list) or not selected or any(mode not in SSH_SOURCE_MODES for mode in selected)
                or len(selected) != len(set(selected)) or ("any" in selected and len(selected) != 1)):
            return ["invalid"]
        return selected
    mode = config.get("ssh_source_mode")
    if mode is None:
        try:
            return ["custom"] if ssh_allowed_ips() else ["local", "vpn"]
        except (TypeError, ValueError):
            return ["invalid"]
    return [mode] if mode in SSH_SOURCE_MODES else ["invalid"]


def ssh_source_networks(mode: str | None = None) -> list[str]:
    """Resolve the selected source mode to the active networks it currently permits."""
    mode = mode or ssh_source_mode()
    if mode == "custom":
        return ssh_allowed_ips()
    if mode in ("local", "vpn"):
        return machine.interface_networks(mode)
    return []


def ssh_client_ip_allowed(client_ip: str) -> bool:
    """Check a Thessley-controlled SSH login's source address against the admin policy."""
    modes = ssh_source_modes()
    if modes == ["any"]:
        return True
    if not modes or any(mode not in ("local", "vpn", "custom") for mode in modes):
        return False  # a malformed restriction must not silently become unrestricted
    try:
        networks = [ipaddress.ip_network(item) for mode in modes for item in ssh_source_networks(mode)]
    except (TypeError, ValueError):
        return False
    if not networks:
        return False  # a selected network class with no detected networks fails closed
    try:
        address = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    return any(address.version == network.version and address in network for network in networks)


def set_ssh_allowed_ips(value: str | list[str] | tuple[str, ...]) -> None:
    """Compatibility wrapper for callers using the earlier custom-list interface."""
    allowed = parse_ssh_allowed_ips(value)
    set_ssh_source_policy("custom" if allowed else "any", allowed)


def set_ssh_source_policy(modes: str | list[str] | tuple[str, ...], addresses: str | list[str] | tuple[str, ...] = "") -> None:
    """Save all-IP, local, VPN, and/or custom-list SSH access."""
    if isinstance(modes, str):
        modes = [modes]
    if (not isinstance(modes, (list, tuple)) or not modes or any(mode not in SSH_SOURCE_MODES for mode in modes)
            or len(modes) != len(set(modes)) or ("any" in modes and len(modes) != 1)):
        raise ValueError("Choose All IPs alone, or one or more of local, VPN, and chosen-list access.")
    allowed = parse_ssh_allowed_ips(addresses) if "custom" in modes else []
    if "custom" in modes and not allowed:
        raise ValueError("Enter at least one IP address or CIDR range for the chosen-list option.")
    store.ensure_dirs()
    config = _load_config()
    if modes == ["any"]:
        # Persist an explicit unrestricted choice. Absence means the safer
        # built-in local+VPN default, not "any".
        config["ssh_source_modes"] = ["any"]
        config.pop("ssh_source_mode", None)
        config.pop("ssh_allowed_ips", None)
    else:
        config["ssh_source_modes"] = list(modes)
        config.pop("ssh_source_mode", None)
    if "custom" in modes:
        config["ssh_allowed_ips"] = allowed
    else:
        config.pop("ssh_allowed_ips", None)
    _atomic_write(_config_path(), config, store.BASE)


def grace_any_ip(service: str) -> bool:
    """Whether this service's grace pass applies regardless of the SSH client's address."""
    try:
        return service not in NO_GRACE and service in _load_config().get("grace_any_ip", [])
    except (TypeError, AttributeError):
        return False


def grace_hours(service: str) -> float:
    """Hours a phone approval stays valid for this PAM service; 0 means every login asks (the default)."""
    if service in NO_GRACE:
        return 0.0
    try:
        hours = float(_load_config().get("grace", {}).get(service, 0))
    except (TypeError, ValueError, AttributeError):
        return 0.0
    return min(max(hours, 0.0), MAX_HOURS)


def requires_phone(service: str, username: str | None = None) -> bool:
    """True if a user with no enrolled (active) phone is refused for this service instead of passing through.
    Off by default, as it is for sudo (so nobody who never opted in is locked out); on for ssh, where the phone is
    the only second step and a missing phone would silently mean no second step at all."""
    if service == "sshd":
        mode = ssh_user_login_mode(username) if username else "inherit"
        if mode == "blocked":
            return True
        policy = _SSH_LOGIN_POLICIES.get(mode)
        if policy is None:
            policy = ssh_login_policy()
        # When the policy permits key+password recovery, an unenrolled user
        # must retain that path. Only phone-only policies require an enrolled
        # device; otherwise the documented fallback mode would lock out new
        # or temporarily unenrolled SSH users.
        return (policy["qr_only"] or policy["key_qr"]) and not policy["key_password"]
    try:
        return service in list(_load_config().get("require", []))
    except TypeError:
        return False


SSH_LOGIN_POLICY_DEFAULT = {"qr_only": False, "key_qr": True, "key_password": True}
# O = keyless, fresh QR approval; K = SSH key + QR; P = SSH key + password.
# Older values remain readable so an upgrade preserves the existing setting.
_SSH_LOGIN_POLICIES = {
    "phone": {"qr_only": False, "key_qr": True, "key_password": False},
    "fallback": {"qr_only": False, "key_qr": True, "key_password": True},
    "password": {"qr_only": False, "key_qr": False, "key_password": True},
    "qr": {"qr_only": True, "key_qr": False, "key_password": False},
    "qr-password": {"qr_only": True, "key_qr": False, "key_password": True},
    "qk": {"qr_only": False, "key_qr": True, "key_password": False},
    "qkp": {"qr_only": False, "key_qr": True, "key_password": True},
    "kp": {"qr_only": False, "key_qr": False, "key_password": True},
    "q": {"qr_only": True, "key_qr": False, "key_password": False},
    "qp": {"qr_only": True, "key_qr": False, "key_password": True},
    "O": {"qr_only": True, "key_qr": False, "key_password": False},
    "K": {"qr_only": False, "key_qr": True, "key_password": False},
    "P": {"qr_only": False, "key_qr": False, "key_password": True},
    "OK": {"qr_only": True, "key_qr": True, "key_password": False},
    "OP": {"qr_only": True, "key_qr": False, "key_password": True},
    "KP": {"qr_only": False, "key_qr": True, "key_password": True},
    "OKP": {"qr_only": True, "key_qr": True, "key_password": True},
}
SSH_LOGIN_MODES = {
    "phone": "SSH key + QR phone approval",
    "fallback": "SSH key + QR phone approval or account password",
    "password": "SSH key + account password",
    "qr": "QR-only (phone approval; no SSH key or account password)",
}
SSH_LOGIN_MODE_PATH = os.path.join(store.BASE, "ssh-login-mode")
SSH_USER_MODE_DIR = os.path.join(store.BASE, "ssh-users")
SSH_DENY_USERS_PATH = "/etc/ssh/sshd_config.d/90-thessley-deny-users.conf"


def _ssh_policy_failure_path() -> str:
    return os.path.join(store.BASE, "ssh-policy-failure")


def ssh_policy_failure_mode() -> str:
    """Behavior if the Linux SSH policy is unreadable: current compatibility default is password fallback."""
    try:
        with open(_ssh_policy_failure_path(), encoding="ascii") as f:
            return "closed" if f.read(16).strip() == "closed" else "fallback"
    except OSError:
        return "fallback"


def set_ssh_policy_failure_mode(mode: str) -> None:
    if mode not in ("fallback", "closed"):
        raise ValueError("Choose fallback or closed.")
    store.ensure_dirs()
    fd, tmp = tempfile.mkstemp(dir=store.BASE, prefix=".tmp.ssh-policy-failure.")
    try:
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write(mode + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, _ssh_policy_failure_path())
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def ssh_user_login_mode(username: str) -> str:
    """Return a per-account SSH override, or inherit when no valid override exists."""
    if not re.fullmatch(r"[a-z_][a-z0-9_.-]{0,31}", username or ""):
        return "inherit"
    try:
        pwd.getpwnam(username)
        with open(os.path.join(SSH_USER_MODE_DIR, username), encoding="ascii") as f:
            mode = f.read(32).strip()
        return mode if mode == "blocked" or mode in _SSH_LOGIN_POLICIES else "inherit"
    except (KeyError, OSError):
        return "inherit"


def ssh_denied_users() -> set[str]:
    """Read Thessley's exact-account sshd deny list; malformed or unsafe files are errors."""
    try:
        fd = os.open(SSH_DENY_USERS_PATH, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return set()
    with os.fdopen(fd, "r", encoding="ascii") as f:
        info = os.fstat(f.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
                or info.st_size > 32768):
            raise OSError("The managed SSH deny file is not a safe root-owned regular file.")
        lines = [line.strip() for line in f if line.strip() and not line.lstrip().startswith("#")]
    if not lines:
        return set()
    if len(lines) != 1 or not lines[0].startswith("DenyUsers "):
        raise OSError("The managed SSH deny file has an unexpected format.")
    users = set(lines[0].split()[1:])
    if not users or any(not re.fullmatch(r"[a-z_][a-z0-9_.-]{0,31}", name) for name in users):
        raise OSError("The managed SSH deny file contains an invalid account name.")
    return users


def ssh_user_is_blocked(username: str) -> bool:
    return username in ssh_denied_users()


def set_ssh_user_blocked(username: str, blocked: bool) -> None:
    """Block or unblock one account in sshd for all SSH auth methods, without restarting sshd."""
    if not re.fullmatch(r"[a-z_][a-z0-9_.-]{0,31}", username or ""):
        raise ValueError("Invalid account name.")
    try:
        pwd.getpwnam(username)
    except KeyError as exc:
        raise ValueError("That account does not exist.") from exc
    config = "/etc/ssh/sshd_config"
    try:
        with open(config, encoding="utf-8") as f:
            main_config = f.read(65536)
    except OSError as exc:
        raise RuntimeError("Cannot read the SSH server configuration; no account was changed.") from exc
    if not re.search(r"(?m)^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf\s*(?:#.*)?$", main_config):
        raise RuntimeError("This SSH server does not include sshd_config.d; no account was changed.")
    users = ssh_denied_users()
    if (username in users) == blocked:
        return
    if blocked:
        users.add(username)
    else:
        users.discard(username)
    content = ("DenyUsers " + " ".join(sorted(users)) + "\n") if users else ""
    path = SSH_DENY_USERS_PATH
    old = None
    try:
        with open(path, "rb") as f:
            old = f.read(32769)
        if len(old) > 32768:
            raise OSError("The managed SSH deny file is too large.")
    except FileNotFoundError:
        pass

    def write_atomic(target: str, data: bytes, mode: int) -> None:
        fd, temp = tempfile.mkstemp(dir=os.path.dirname(target), prefix=".tmp.thessley-ssh.")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(temp, mode)
            if os.geteuid() == 0:
                os.chown(temp, 0, 0)
            os.replace(temp, target)
        except BaseException:
            if os.path.exists(temp):
                os.unlink(temp)
            raise

    if old is not None:
        write_atomic(path + ".bak", old, 0o600)
    reload_attempted = False
    try:
        if content:
            write_atomic(path, content.encode("ascii"), 0o644)
        else:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
        check = subprocess.run(["/usr/sbin/sshd", "-t"], stdin=subprocess.DEVNULL,
                               capture_output=True, text=True, timeout=15, check=False)
        if check.returncode:
            raise RuntimeError("sshd rejected the access rule; it was rolled back. " + check.stderr[-500:].strip())
        reload_attempted = True
        reload_result = subprocess.run(["systemctl", "reload", "ssh"], stdin=subprocess.DEVNULL,
                                       capture_output=True, text=True, timeout=15, check=False)
        if reload_result.returncode:
            raise RuntimeError("Could not reload SSH; the account rule was rolled back. " + reload_result.stderr[-500:].strip())
    except BaseException:
        if old is None:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
        else:
            write_atomic(path, old, 0o644)
        if reload_attempted:
            subprocess.run(["systemctl", "reload", "ssh"], stdin=subprocess.DEVNULL,
                           capture_output=True, text=True, timeout=15, check=False)
        raise


def set_ssh_user_login_mode(username: str, mode: str) -> None:
    """Atomically save or remove one user's policy override; backups retain the prior value."""
    if not re.fullmatch(r"[a-z_][a-z0-9_.-]{0,31}", username or ""):
        raise ValueError("Invalid account name.")
    try:
        pwd.getpwnam(username)
    except KeyError as exc:
        raise ValueError("That account does not exist.") from exc
    if mode in SSH_LOGIN_MODES:
        policy = _SSH_LOGIN_POLICIES[mode]
        mode = ("O" if policy["qr_only"] else "") + ("K" if policy["key_qr"] else "") + ("P" if policy["key_password"] else "")
    if mode not in {"inherit", "blocked", *_SSH_LOGIN_POLICIES.keys()}:
        raise ValueError("Choose a supported per-user SSH policy.")
    os.makedirs(SSH_USER_MODE_DIR, mode=0o700, exist_ok=True)
    os.chmod(SSH_USER_MODE_DIR, 0o700)
    path = os.path.join(SSH_USER_MODE_DIR, username)
    try:
        with open(path, "rb") as previous:
            old_value = previous.read(64)
        backup = path + ".bak"
        backup_fd, backup_tmp = tempfile.mkstemp(dir=SSH_USER_MODE_DIR, prefix=".tmp.ssh-user.bak.")
        try:
            with os.fdopen(backup_fd, "wb") as f:
                f.write(old_value)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(backup_tmp, 0o600)
            os.replace(backup_tmp, backup)
        except BaseException:
            if os.path.exists(backup_tmp):
                os.unlink(backup_tmp)
            raise
    except FileNotFoundError:
        pass
    if mode == "inherit":
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        return
    fd, tmp = tempfile.mkstemp(dir=SSH_USER_MODE_DIR, prefix=".tmp.ssh-user.")
    try:
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write(mode + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def ssh_user_login_policy(username: str) -> dict[str, bool]:
    """Return a user's effective SSH login paths, including a blocked marker."""
    mode = ssh_user_login_mode(username)
    if mode == "blocked":
        return {"qr_only": False, "key_qr": False, "key_password": False, "blocked": True}
    if mode == "inherit":
        policy = ssh_login_policy()
    else:
        policy = dict(_SSH_LOGIN_POLICIES.get(mode, SSH_LOGIN_POLICY_DEFAULT))
    return {**policy, "blocked": False}


def set_ssh_user_login_paths(username: str, inherit: bool, qr_only: bool, key_qr: bool,
                             key_password: bool, blocked: bool) -> None:
    if inherit:
        set_ssh_user_blocked(username, False)
        set_ssh_user_login_mode(username, "inherit")
    elif blocked:
        if qr_only or key_qr or key_password:
            raise ValueError("A blocked account cannot also have an allowed login path.")
        set_ssh_user_blocked(username, True)
        set_ssh_user_login_mode(username, "blocked")
    elif qr_only or key_qr or key_password:
        set_ssh_user_blocked(username, False)
        mode = ("O" if qr_only else "") + ("K" if key_qr else "") + ("P" if key_password else "")
        set_ssh_user_login_mode(username, mode)
    else:
        raise ValueError("Select at least one login path, select Block SSH, or choose Use global policy.")


def ssh_login_policy() -> dict[str, bool]:
    """Return enabled SSH paths. Missing or invalid settings default to key + QR with key + password recovery."""
    try:
        with open(SSH_LOGIN_MODE_PATH, encoding="ascii") as f:
            value = f.read(32).strip()
        policy = _SSH_LOGIN_POLICIES.get(value, SSH_LOGIN_POLICY_DEFAULT)
        return dict(policy)
    except OSError:
        return dict(SSH_LOGIN_POLICY_DEFAULT)


def set_ssh_login_paths(qr_only: bool, key_qr: bool, key_password: bool) -> None:
    """Atomically set allowed SSH paths, retaining the previous policy as a backup."""
    if not (qr_only or key_qr or key_password):
        raise ValueError("Select at least one SSH login path.")
    value = ("O" if qr_only else "") + ("K" if key_qr else "") + ("P" if key_password else "")
    store.ensure_dirs()
    try:
        with open(SSH_LOGIN_MODE_PATH, "rb") as previous:
            old_value = previous.read(32)
        backup = SSH_LOGIN_MODE_PATH + ".bak"
        backup_fd, backup_tmp = tempfile.mkstemp(dir=store.BASE, prefix=".tmp.ssh-login-mode.bak.")
        try:
            with os.fdopen(backup_fd, "wb") as f:
                f.write(old_value)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(backup_tmp, 0o600)
            os.replace(backup_tmp, backup)
        except BaseException:
            if os.path.exists(backup_tmp):
                os.unlink(backup_tmp)
            raise
    except FileNotFoundError:
        pass
    fd, tmp = tempfile.mkstemp(dir=store.BASE, prefix=".tmp.ssh-login-mode.")
    try:
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write(value + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, SSH_LOGIN_MODE_PATH)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def set_ssh_login_policy(qr: bool, qr_key: bool, password: bool) -> None:
    """Compatibility wrapper for the previous three-flag policy API."""
    set_ssh_login_paths(qr and not qr_key, qr and qr_key, password)


def set_ssh_login_mode(mode: str) -> None:
    """Compatibility wrapper for the earlier single-choice admin setting."""
    if mode not in SSH_LOGIN_MODES:
        raise ValueError("Choose phone, fallback, password, or qr.")
    policy = _SSH_LOGIN_POLICIES[mode]
    set_ssh_login_paths(policy["qr_only"], policy["key_qr"], policy["key_password"])


def ssh_login_mode() -> str:
    """Compatibility name for older integrations; policy details live in ssh_login_policy()."""
    policy = ssh_login_policy()
    if policy == {"qr_only": True, "key_qr": False, "key_password": False}:
        return "qr"
    if policy["key_qr"] and policy["key_password"]:
        return "fallback"
    if policy["key_qr"]:
        return "phone"
    return "password"


def self_enroll_allowed() -> bool:
    """May a user with no phone enrol their first one themselves (thessley-pam enroll-me)? On unless switched off."""
    try:
        return bool(_load_config().get("self_enroll", True))
    except (TypeError, AttributeError):
        return True


def set_self_enroll(on: bool) -> None:
    store.ensure_dirs()
    data = _load_config()
    if on:
        data.pop("self_enroll", None)  # the default
    else:
        data["self_enroll"] = False
    _atomic_write(_config_path(), data, store.BASE)


WEB_DEFAULTS = {"enabled": False, "listen": "", "port": 47820, "session_minutes": 15, "cert": "", "key": "",
                "max_connections": 32, "rate_limit_entries": 4096, "localhost_only": False}


VPN_DEFAULTS = {"enabled": False, "public_host": "", "server_port": 1194, "page_port": 47830,
                "socket_group": "nogroup", "wait": 180}


def vpn_settings() -> dict:
    """The OpenVPN second step's settings (thessley-pam vpn ...). public_host is the name or address the device is told to
    connect to for the approval (the router forwards it to this computer); page_port is the public QR page."""
    out = dict(VPN_DEFAULTS)
    try:
        raw = _load_config().get("vpn", {})
        if isinstance(raw, dict):
            out.update({k: v for k, v in raw.items() if k in VPN_DEFAULTS})
    except (TypeError, AttributeError):
        pass
    try:
        out["server_port"] = min(max(int(out["server_port"]), 1), 65535)
        out["page_port"] = min(max(int(out["page_port"]), 1), 65535)
        out["wait"] = min(max(int(out["wait"]), 30), 600)
    except (TypeError, ValueError):
        out["server_port"], out["page_port"], out["wait"] = (
            VPN_DEFAULTS["server_port"], VPN_DEFAULTS["page_port"], VPN_DEFAULTS["wait"]
        )
    out["enabled"] = bool(out["enabled"])
    return out


def set_vpn(**changes) -> dict:
    unknown = set(changes) - set(VPN_DEFAULTS)
    if unknown:
        raise ValueError(f"unknown vpn setting: {sorted(unknown)}")
    store.ensure_dirs()
    data = _load_config()
    vpn = data.get("vpn") if isinstance(data.get("vpn"), dict) else {}
    vpn.update(changes)
    data["vpn"] = vpn
    _atomic_write(_config_path(), data, store.BASE)
    return vpn_settings()


def web_settings() -> dict:
    """The admin web page's settings (thessley-pam web ...). listen "" means this computer's LAN address."""
    out = dict(WEB_DEFAULTS)
    try:
        raw = _load_config().get("web", {})
        if isinstance(raw, dict):
            out.update({k: v for k, v in raw.items() if k in WEB_DEFAULTS})
    except (TypeError, AttributeError):
        pass
    try:
        out["port"] = min(max(int(out["port"]), 1), 65535)
        out["session_minutes"] = min(max(int(out["session_minutes"]), 1), 240)
        out["max_connections"] = min(max(int(out["max_connections"]), 4), 256)
        out["rate_limit_entries"] = min(max(int(out["rate_limit_entries"]), 64), 100000)
    except (TypeError, ValueError):
        out["port"], out["session_minutes"] = WEB_DEFAULTS["port"], WEB_DEFAULTS["session_minutes"]
        out["max_connections"], out["rate_limit_entries"] = WEB_DEFAULTS["max_connections"], WEB_DEFAULTS["rate_limit_entries"]
    out["enabled"] = bool(out["enabled"])
    out["localhost_only"] = bool(out["localhost_only"])
    return out


def set_web(**changes) -> dict:
    unknown = set(changes) - set(WEB_DEFAULTS)
    if unknown:
        raise ValueError(f"unknown web setting: {sorted(unknown)}")
    store.ensure_dirs()
    data = _load_config()
    web = data.get("web") if isinstance(data.get("web"), dict) else {}
    web.update(changes)
    data["web"] = web
    _atomic_write(_config_path(), data, store.BASE)
    return web_settings()


def set_require(service: str, on: bool) -> None:
    if not service or any(c in service for c in "/ \t\n\0") or service.startswith("."):
        raise ValueError("bad service name")
    if service == "sshd":
        # Keep the legacy CLI switch meaningful: disabling the phone selects account-password auth rather than
        # allowing SSH through with no second factor.
        set_ssh_login_policy(qr=on, qr_key=True, password=not on)
        return
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


def set_grace(service: str, hours: float, ip_scope: str | None = None) -> None:
    if not service or any(c in service for c in "/ \t\n\0") or service.startswith("."):
        raise ValueError("bad service name")
    hours = min(max(float(hours), 0.0), MAX_HOURS)
    if service in NO_GRACE and hours > 0:
        raise ValueError("The VPN always asks for an approval: there is no grace time for it.")
    if ip_scope not in (None, "same", "any"):
        raise ValueError("IP scope must be 'same' or 'any'.")
    store.ensure_dirs()
    data = _load_config()
    grace = data.setdefault("grace", {})
    if hours > 0:
        grace[service] = hours
    else:
        grace.pop(service, None)
    if ip_scope is not None:
        any_ip = set(data.get("grace_any_ip", []))
        if ip_scope == "any":
            any_ip.add(service)
        else:
            any_ip.discard(service)
        if any_ip:
            data["grace_any_ip"] = sorted(any_ip)
        else:
            data.pop("grace_any_ip", None)
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
    # This directory also contains vpn.sock, which OpenVPN's auth hook opens as
    # nobody:nogroup. Keep the shared parent traversable by that group; only the
    # grants subdirectory and its files are private to root.
    os.makedirs(RUN, mode=0o750, exist_ok=True)
    if os.geteuid() == 0:
        os.chown(RUN, 0, grp.getgrnam("nogroup").gr_gid)
    os.chmod(RUN, 0o750)
    os.makedirs(GRANTS, mode=0o700, exist_ok=True)
    # RUN is shared with the phone approval sockets. Keep its systemd-managed
    # traversal permissions; protect pass files in the private GRANTS dir.
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


def passes_of(username: str, now: float | None = None) -> list[dict]:
    """The live passes of one account."""
    now = time.time() if now is None else now
    try:
        return _live(_load(username), now)
    except KeyError:
        return []


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


def revoke_one(username: str, service: str, rhost: str) -> int:
    """End the one pass for this user, service and client address. Returns how many ended (0 or 1)."""
    items = _load(username)
    keep = [i for i in items if not (i.get("service") == service and i.get("rhost") == rhost)]
    if len(keep) != len(items):
        _save(username, keep)
    return len(items) - len(keep)


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
