"""
Outbound network guard.

Every request the server makes on behalf of a caller (port scans, header scans,
robots/security.txt fetches, URL behaviour analysis) goes through this module so
that a caller cannot point the server at loopback, RFC1918, link-local (cloud
metadata at 169.254.169.254), CGNAT, multicast or other reserved address space.

Set ALLOW_PRIVATE_TARGETS=true only for an isolated lab where scanning internal
hosts is the point.
"""
import ipaddress
import os
import socket
from typing import Iterable, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests

MAX_REDIRECTS = 5


class BlockedTargetError(ValueError):
    """Raised when a target resolves to a non-public address."""


def private_targets_allowed() -> bool:
    return os.getenv("ALLOW_PRIVATE_TARGETS", "false").strip().lower() == "true"


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def resolve_host(host: str) -> Iterable[str]:
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return sorted({info[4][0] for info in infos})


def check_host(host: str, require_resolution: bool = False) -> Tuple[bool, Optional[str]]:
    """Return (ok, error). A host is ok when every address it resolves to is public."""
    if not host:
        return False, "Host is required"
    if private_targets_allowed():
        return True, None
    host = host.strip().strip("[]").lower()
    try:
        ipaddress.ip_address(host)
        return (True, None) if is_public_ip(host) else (False, "Private, loopback or reserved addresses cannot be targeted")
    except ValueError:
        pass
    try:
        addrs = resolve_host(host)
    except (socket.gaierror, UnicodeError):
        if require_resolution:
            return False, f"Host does not resolve: {host}"
        return True, None
    blocked = [a for a in addrs if not is_public_ip(a)]
    if blocked:
        return False, f"{host} resolves to a non-public address"
    return True, None


def assert_public_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise BlockedTargetError("Only http and https URLs are allowed")
    ok, err = check_host(parsed.hostname or "", require_resolution=True)
    if not ok:
        raise BlockedTargetError(err)


def safe_get(url: str, **kwargs) -> requests.Response:
    """requests.get that re-validates the destination on every redirect hop."""
    follow = kwargs.pop("allow_redirects", True)
    kwargs.setdefault("timeout", 10)
    current = url
    history = []
    for _ in range(MAX_REDIRECTS + 1):
        assert_public_url(current)
        resp = requests.get(current, allow_redirects=False, **kwargs)
        if not (follow and resp.is_redirect):
            resp.history = history
            return resp
        history.append(resp)
        current = urljoin(current, resp.headers.get("Location", ""))
    raise BlockedTargetError("Too many redirects")
