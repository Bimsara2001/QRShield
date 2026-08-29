"""Strict pre-resolution validation for public HTTP(S) destinations.

This module deliberately has no FastAPI, Playwright, Docker, database, or
threat-intelligence dependency so it can be used by both the API and future
sandbox navigation controls.

Important: resolving a hostname before navigation reduces SSRF exposure but
does not fully prevent DNS rebinding. Chromium can resolve the hostname again
when it connects. A later stage must enforce the same policy at browser-time
egress, rather than relying on this pre-resolution check alone.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlsplit


class URLValidationError(ValueError):
    """Raised when a URL is malformed or is not a public web destination."""


_ALLOWED_SCHEMES = {"http", "https"}
_LOCAL_HOST_ALIASES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "broadcasthost",
}
_NUMERIC_HOST_PART = re.compile(r"(?:0[xX][0-9a-fA-F]+|0[0-7]*|[0-9]+)")


def _parse_number(value: str) -> int | None:
    """Parse a decimal, legacy-octal, or hexadecimal IPv4 number component."""
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
    """Recognize browser-compatible abbreviated numeric IPv4 forms.

    For example, ``127.1`` means ``127.0.0.1`` in common URL parsers. Treating
    these as DNS names could allow loopback bypasses on platforms that resolve
    them locally.
    """
    parts = hostname.split(".")
    if not 1 <= len(parts) <= 4:
        return None

    numbers = [_parse_number(part) for part in parts]
    if any(number is None for number in numbers):
        return None

    values = [int(number) for number in numbers]
    if len(values) == 4:
        if any(value > 0xFF for value in values):
            return None
        integer = (
            (values[0] << 24)
            | (values[1] << 16)
            | (values[2] << 8)
            | values[3]
        )
    else:
        leading_count = len(values) - 1
        if any(value > 0xFF for value in values[:leading_count]):
            return None
        final_bits = 8 * (5 - len(values))
        if values[-1] >= (1 << final_bits):
            return None

        integer = values[-1]
        for index, value in enumerate(values[:-1]):
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
    """Reject every destination class that is not globally routable."""
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        _ensure_public_ip(address.ipv4_mapped)
        return

    # is_global is intentionally conservative: it rejects loopback, private,
    # link-local, unspecified, multicast, reserved, and shared/non-global IPs.
    if not address.is_global:
        raise URLValidationError("URL resolves to a non-public IP address.")


def _validate_hostname(hostname: str) -> str:
    normalized = hostname.rstrip(".").lower()
    if not normalized:
        raise URLValidationError("URL must include a hostname.")

    if normalized in _LOCAL_HOST_ALIASES or normalized.endswith(".localhost"):
        raise URLValidationError("Local hostnames are not allowed.")

    if "%" in hostname or any(character.isspace() for character in hostname):
        raise URLValidationError("URL hostname is malformed.")

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
        raise URLValidationError("URL hostname could not be resolved.") from exc

    addresses: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    for family, _, _, _, sockaddr in records:
        if family == socket.AF_INET:
            raw_address = sockaddr[0]
        elif family == socket.AF_INET6:
            raw_address = sockaddr[0]
        else:
            raise URLValidationError("URL hostname resolved to an unsupported address type.")

        try:
            addresses.add(ipaddress.ip_address(raw_address))
        except ValueError as exc:
            raise URLValidationError("URL hostname resolved to an invalid IP address.") from exc

    if not addresses:
        raise URLValidationError("URL hostname did not resolve to an IP address.")

    # Every record must be public. One private result rejects the hostname.
    for address in addresses:
        _ensure_public_ip(address)


def validate_public_url(url: str) -> str:
    """Validate an HTTP(S) URL whose destination is publicly routable.

    The returned string is the input with outer whitespace removed. Paths,
    query strings, fragments, ports, and hostname casing are otherwise left
    intact for the later browser request. Unsafe/malformed URLs raise
    :class:`URLValidationError` with a safe, user-facing reason.
    """
    if not isinstance(url, str) or not url.strip():
        raise URLValidationError("URL must be a non-empty string.")

    normalized_url = url.strip()
    try:
        parsed = urlsplit(normalized_url)
    except ValueError as exc:
        raise URLValidationError("URL is malformed.") from exc

    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        raise URLValidationError("Only http and https URLs are allowed.")

    if parsed.username is not None or parsed.password is not None:
        raise URLValidationError("URLs containing credentials are not allowed.")

    try:
        port = parsed.port
    except ValueError as exc:
        raise URLValidationError("URL contains an invalid port.") from exc

    if port is not None and not 1 <= port <= 65535:
        raise URLValidationError("URL contains an invalid port.")

    if parsed.hostname is None:
        raise URLValidationError("URL must include a hostname.")

    hostname = _validate_hostname(parsed.hostname)
    address = _parse_ip_address(hostname)
    if address is not None:
        _ensure_public_ip(address)
    else:
        _resolve_and_validate(hostname)

    return normalized_url
