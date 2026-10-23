"""Facts about this computer that go into QR codes."""

import hashlib
import ipaddress
import json
import re
import socket
import subprocess


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


def interface_networks(kind: str) -> list[str]:
    """Discover directly attached local or VPN networks from active Linux interfaces."""
    if kind not in ("local", "vpn"):
        raise ValueError("Network kind must be 'local' or 'vpn'.")
    try:
        result = subprocess.run(["ip", "-j", "address", "show"], stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, timeout=3, check=False)
        links = json.loads(result.stdout) if result.returncode == 0 else []
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return []
    networks = set()
    for link in links if isinstance(links, list) else []:
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
