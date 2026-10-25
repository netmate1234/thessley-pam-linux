"""Facts about this computer that go into QR codes."""

import hashlib
import ipaddress
import json
import re
import socket
import subprocess
import threading
import time


def machine_id() -> str:
    """A stable id for this computer, derived from /etc/machine-id without revealing it.

    The phone stores computers under this, not the IP address, so a new DHCP lease doesn't break anything.
    """
    with open("/etc/machine-id") as f:
        raw = f.read().strip()
    return hashlib.sha256(f"thessley-pam-v1:{raw}".encode()).hexdigest()[:32]


def hostname() -> str:
    return socket.gethostname()


def lan_ip() -> str:
    """The address this computer uses to reach its default gateway (no packet is sent)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("192.0.2.1", 9))  # TEST-NET-1, never routed
        return s.getsockname()[0]


_VPN_IFACE = re.compile(r"^(?:tun|tap|wg|tailscale|zt|vpn|ovpn|thessley)", re.IGNORECASE)
_VIRTUAL_IFACE = re.compile(r"^(?:docker|br-|veth|virbr|podman|cni)", re.IGNORECASE)
_PRIVATE_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"))
_INTERFACE_CACHE: tuple[float, list[dict] | None] = (0.0, None)
_INTERFACE_CACHE_LOCK = threading.Lock()
_INTERFACE_REFRESHING = False


def _read_interface_snapshot() -> list[dict]:
    """Read active interface addresses once and cache the shared snapshot."""
    global _INTERFACE_CACHE
    try:
        result = subprocess.run(["ip", "-j", "address", "show"], stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, timeout=3, check=False)
        links = json.loads(result.stdout) if result.returncode == 0 else []
    except (OSError, subprocess.TimeoutExpired, ValueError):
        raise
    if not isinstance(links, list):
        links = []
    with _INTERFACE_CACHE_LOCK:
        _INTERFACE_CACHE = (time.monotonic(), links)
    return links


def _refresh_interface_snapshot_background() -> None:
    global _INTERFACE_REFRESHING
    try:
        _read_interface_snapshot()
    except Exception:
        pass  # Keep the last known network list usable if a refresh fails.
    finally:
        with _INTERFACE_CACHE_LOCK:
            _INTERFACE_REFRESHING = False


def _interface_snapshot() -> list[dict]:
    global _INTERFACE_REFRESHING
    with _INTERFACE_CACHE_LOCK:
        cached_at, cached = _INTERFACE_CACHE
        if cached is not None:
            if time.monotonic() - cached_at >= 60 and not _INTERFACE_REFRESHING:
                _INTERFACE_REFRESHING = True
                threading.Thread(target=_refresh_interface_snapshot_background, daemon=True).start()
            return list(cached)
    try:
        return _read_interface_snapshot()
    except (OSError, subprocess.SubprocessError, ValueError):
        with _INTERFACE_CACHE_LOCK:
            _, cached = _INTERFACE_CACHE
        return list(cached) if cached is not None else []


def interface_networks(kind: str) -> list[str]:
    """Return cached local or VPN networks, refreshing stale interface data in background."""
    if kind not in ("local", "vpn"):
        raise ValueError("Network kind must be 'local' or 'vpn'.")
    links = _interface_snapshot()
    networks = set()
    for link in links:
        name = str(link.get("ifname", ""))
        is_vpn = bool(_VPN_IFACE.match(name))
        if name == "lo" or (kind == "vpn") != is_vpn or (kind == "local" and _VIRTUAL_IFACE.match(name)):
            continue
        for info in link.get("addr_info", []):
            if info.get("scope") not in ("global", "site"):
                continue
            address = info.get("local")
            prefix = info.get("prefixlen")
            try:
                interface = ipaddress.ip_interface(f"{address}/{prefix}")
            except (ValueError, TypeError):
                continue
            if interface.ip.is_loopback or interface.ip.is_link_local or interface.network.prefixlen == 0:
                continue
            if kind == "local" and not any(interface.network.subnet_of(private) for private in _PRIVATE_NETWORKS
                                            if private.version == interface.network.version):
                continue
            networks.add(str(interface.network))
    return sorted(networks, key=lambda item: (ipaddress.ip_network(item).version, int(ipaddress.ip_network(item).network_address), ipaddress.ip_network(item).prefixlen))
