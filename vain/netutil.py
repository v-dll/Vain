"""Tiny helpers for matching hosts against IP / CIDR / hostname specs."""

from __future__ import annotations

import fnmatch
import ipaddress


def specificity(spec: str, address: str, hostname: str = "") -> int | None:
    """How specifically ``spec`` matches this host, or None if it doesn't.

    Exact IP = 200, hostname glob = 150, CIDR = its prefix length (0-128),
    so the most specific rule can win when several match.
    """
    spec = str(spec).strip()
    try:
        addr = ipaddress.ip_address(address)
    except ValueError:
        return None
    try:
        if "/" in spec:
            net = ipaddress.ip_network(spec, strict=False)
            return net.prefixlen if addr.version == net.version and addr in net else None
        return 200 if addr == ipaddress.ip_address(spec) else None
    except ValueError:
        pass
    if hostname and fnmatch.fnmatch(hostname.lower(), spec.lower()):
        return 150
    return None


def in_scope(scope: list[str], address: str, hostname: str = "") -> bool:
    """Empty scope means 'applies everywhere'."""
    if not scope:
        return True
    return any(specificity(s, address, hostname) is not None for s in scope)
