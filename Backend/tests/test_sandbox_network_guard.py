import socket
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from sandbox.network_guard import NetworkGuardError, validate_request_destination


PUBLIC_V4 = "93.184.216.34"
PUBLIC_V6 = "2606:2800:220:1:248:1893:25c8:1946"
SANDBOX_DIRECTORY = Path(__file__).resolve().parents[1] / "sandbox"
sys.path.insert(0, str(SANDBOX_DIRECTORY))
import worker as sandbox_worker  # noqa: E402


def dns_records(*addresses: str):
    records = []
    for address in addresses:
        if ":" in address:
            records.append((socket.AF_INET6, socket.SOCK_STREAM, 6, "", (address, 0, 0, 0)))
        else:
            records.append((socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 0)))
    return records


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/resource.js",
        "https://cdn.example.com/image.png",
    ],
)
@patch("sandbox.network_guard.socket.getaddrinfo")
def test_allows_public_hostname_requests(mock_getaddrinfo, url):
    mock_getaddrinfo.return_value = dns_records(PUBLIC_V4)

    validate_request_destination(url)


@patch("sandbox.network_guard.socket.getaddrinfo")
def test_allows_public_ipv6_hostname_result(mock_getaddrinfo):
    mock_getaddrinfo.return_value = dns_records(PUBLIC_V6)

    validate_request_destination("https://ipv6-public.example/font.woff2")


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost/x",
        "http://localhost./x",
        "http://subdomain.localhost/x",
        "http://127.0.0.1/x",
        "http://10.0.0.1/x",
        "http://172.16.1.1/x",
        "http://192.168.1.1/x",
        "http://169.254.169.254/x",
        "http://[::1]/x",
        "http://[fe80::1]/x",
        "http://[fc00::1]/x",
        "http://[::ffff:127.0.0.1]/x",
    ],
)
def test_blocks_unsafe_literal_destinations(url):
    with pytest.raises(NetworkGuardError):
        validate_request_destination(url)


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "192.168.1.10", "169.254.169.254", "fe80::1234", "fc00::1234"],
)
@patch("sandbox.network_guard.socket.getaddrinfo")
def test_blocks_hostname_with_non_public_dns_answer(mock_getaddrinfo, address):
    mock_getaddrinfo.return_value = dns_records(address)

    with pytest.raises(NetworkGuardError):
        validate_request_destination("https://public-looking.example/resource")


@patch("sandbox.network_guard.socket.getaddrinfo")
def test_blocks_mixed_public_and_private_dns_answers(mock_getaddrinfo):
    mock_getaddrinfo.return_value = dns_records(PUBLIC_V4, "192.168.1.10")

    with pytest.raises(NetworkGuardError):
        validate_request_destination("https://mixed-answer.example/resource")


@patch("sandbox.network_guard.socket.getaddrinfo")
def test_blocks_dns_failure(mock_getaddrinfo):
    mock_getaddrinfo.side_effect = socket.gaierror("DNS failure")

    with pytest.raises(NetworkGuardError):
        validate_request_destination("https://unresolved.example/resource")


@pytest.mark.parametrize("url", ["about:blank", "data:text/plain,worker", "blob:https://example.com/id"])
def test_allows_browser_internal_non_network_urls(url):
    validate_request_destination(url)


class FakeRequest:
    def __init__(self, url):
        self.url = url


class FakeRoute:
    def __init__(self, url):
        self.request = FakeRequest(url)
        self.continued = False
        self.abort_reason = None

    def continue_(self):
        self.continued = True

    def abort(self, reason):
        self.abort_reason = reason


class FakeWebSocketRoute:
    def __init__(self):
        self.close_args = None

    def close(self, *, code=None, reason=None):
        self.close_args = {"code": code, "reason": reason}


def test_worker_route_continues_safe_request():
    route = FakeRoute("https://example.com/script.js")
    with patch.object(sandbox_worker, "validate_request_destination"):
        sandbox_worker._guard_route(route)

    assert route.continued is True
    assert route.abort_reason is None


def test_worker_route_uses_proxy_mode_without_worker_dns_resolution():
    route = FakeRoute("https://example.com/script.js")
    with patch.object(sandbox_worker, "validate_request_destination") as validate:
        sandbox_worker._guard_route(route, proxy_mode=True)

    assert route.continued is True
    validate.assert_called_once_with(
        "https://example.com/script.js",
        resolve_hostname_dns=False,
    )


def test_worker_route_aborts_unsafe_or_unexpected_validation_failure():
    route = FakeRoute("http://127.0.0.1/private")
    with patch.object(
        sandbox_worker,
        "validate_request_destination",
        side_effect=NetworkGuardError("blocked"),
    ):
        sandbox_worker._guard_route(route)

    assert route.continued is False
    assert route.abort_reason == "blockedbyclient"


def test_worker_blocks_web_sockets_before_connection():
    web_socket_route = FakeWebSocketRoute()

    sandbox_worker._block_web_socket(web_socket_route)

    assert web_socket_route.close_args == {"code": 1008, "reason": "Blocked by QRShield"}
