"""IP validation and blocklist checking."""

import ipaddress
from config import BLOCKLIST


def validate_ip(ip_str: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Validate that ip_str is a single valid IPv4 or IPv6 address.

    Raises ValueError for hostnames, CIDR ranges, or malformed input.
    """
    # Reject anything with a slash (CIDR) or whitespace
    if "/" in ip_str or ip_str != ip_str.strip():
        raise ValueError("Only a single IP address is allowed (no CIDR ranges).")

    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        raise ValueError(f"'{ip_str}' is not a valid IP address.")

    return addr


def is_blocked(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Check if the given IP address falls within any blocklisted CIDR range."""
    for cidr in BLOCKLIST:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            if addr in network:
                return True
        except ValueError:
            # Invalid blocklist entry — skip it
            continue
    return False
