"""Per-request public-network guard for the isolated browser worker.

This is browser-level defense in depth. DNS validation happens before
Chromium opens a connection, but Chromium performs its own later resolution,
so this module cannot fully prevent DNS rebinding or replace network-layer
egress controls.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlsplit


class NetworkGuardError(ValueError):
    """Raised when a browser request is not safe to continue."""


_NETWORK_SCHEMES = {"http", "https"}
_INTERNAL_SCHEMES = {"about", "blob", "data"}
_LOCAL_HOST_ALIASES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "broadcasthost",
    "host.docker.internal",
    "gateway.docker.internal",
}
_NUMERIC_HOST_PART = re.compile(r"(?:0[xX][0-9a-fA-F]+|0[0-7]*|[0-9]+)")


def _parse_number(value: str) -> int | None:
    if not _NUMERIC_HOST_PART.fullmatch(value):
        return None

    try:
        if value.lower().startswith("0x"):
            return int(value[2:], 16)
        if len(value) > 1 and value.startswith("0"):
            return int(value, 8)
        return int(value, 10)
    except ValueError:
        return None


def _parse_legacy_ipv4(hostname: str) -> ipaddress.IPv4Address | None:
    """Recognize abbreviated numeric IPv4 forms such as ``127.1``."""
    parts = hostname.split(".")
    if not 1 <= len(parts) <= 4:
        return None

    values = [_parse_number(part) for part in parts]
    if any(value is None for value in values):
        return None

    numbers = [int(value) for value in values]
    if len(numbers) == 4:
        if any(value > 0xFF for value in numbers):
            return None
        integer = (
            (numbers[0] << 24)
            | (numbers[1] << 16)
            | (numbers[2] << 8)
            | numbers[3]
        )
    else:
        leading_count = len(numbers) - 1
        if any(value > 0xFF for value in numbers[:leading_count]):
            return None
        final_bits = 8 * (5 - len(numbers))
        if numbers[-1] >= (1 << final_bits):
            return None

        integer = numbers[-1]
        for index, value in enumerate(numbers[:-1]):
            integer |= value << (24 - (index * 8))

    try:
        return ipaddress.IPv4Address(integer)
    except ipaddress.AddressValueError:
        return None


def _parse_ip_address(hostname: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(hostname)
    except ValueError:
        return _parse_legacy_ipv4(hostname)


def _ensure_public_ip(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        _ensure_public_ip(address.ipv4_mapped)
        return

    if not address.is_global:
        raise NetworkGuardError("Request destination is not publicly routable.")


def _validate_hostname(hostname: str) -> str:
    normalized = hostname.rstrip(".").lower()
    if not normalized:
        raise NetworkGuardError("Request URL has no hostname.")
    if normalized in _LOCAL_HOST_ALIASES or normalized.endswith(".localhost"):
        raise NetworkGuardError("Local hostnames are blocked.")
    if "%" in hostname or any(character.isspace() for character in hostname):
        raise NetworkGuardError("Request hostname is malformed.")
    return normalized


def _resolve_and_validate(hostname: str) -> None:
    try:
        records = socket.getaddrinfo(
            hostname,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
    except (socket.gaierror, OSError) as exc:
        raise NetworkGuardError("Request hostname could not be resolved.") from exc

    addresses: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    for family, _, _, _, sockaddr in records:
        if family not in {socket.AF_INET, socket.AF_INET6}:
            raise NetworkGuardError("Request hostname has an unsupported address type.")
        try:
            addresses.add(ipaddress.ip_address(sockaddr[0]))
        except (IndexError, ValueError, TypeError) as exc:
            raise NetworkGuardError("Request hostname resolved to an invalid address.") from exc

    if not addresses:
        raise NetworkGuardError("Request hostname did not resolve to an address.")

    for address in addresses:
        _ensure_public_ip(address)


def validate_request_destination(url: str, *, resolve_hostname_dns: bool = True) -> None:
    """Allow only safe HTTP(S) destinations or non-network browser URLs.

    In direct mode, no DNS result is cached: each routed request resolves its
    hostname again within its own short-lived worker process. In proxy mode,
    callers set ``resolve_hostname_dns=False``. Literal IP and local-alias
    checks still happen here, while the egress proxy becomes the authoritative
    resolver and destination-IP enforcement point for ordinary hostnames.
    """
    if not isinstance(url, str) or not url:
        raise NetworkGuardError("Request URL is invalid.")

    try:
        parsed = urlsplit(url)
    except ValueError as exc:
        raise NetworkGuardError("Request URL is malformed.") from exc

    scheme = parsed.scheme.lower()
    if scheme in _INTERNAL_SCHEMES:
        return
    if scheme not in _NETWORK_SCHEMES:
        raise NetworkGuardError("Request scheme is not allowed.")
    if parsed.username is not None or parsed.password is not None:
        raise NetworkGuardError("Request URL credentials are not allowed.")

    try:
        port = parsed.port
    except ValueError as exc:
        raise NetworkGuardError("Request URL contains an invalid port.") from exc
    if port is not None and not 1 <= port <= 65535:
        raise NetworkGuardError("Request URL contains an invalid port.")
    if parsed.hostname is None:
        raise NetworkGuardError("Request URL has no hostname.")

    hostname = _validate_hostname(parsed.hostname)
    address = _parse_ip_address(hostname)
    if address is not None:
        _ensure_public_ip(address)
    elif resolve_hostname_dns:
        _resolve_and_validate(hostname)
