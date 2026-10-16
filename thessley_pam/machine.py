"""Facts about this computer that go into QR codes."""

import hashlib
import socket


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
