import io
import socket
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from sandbox.network_guard import NetworkGuardError, validate_request_destination


SANDBOX_DIRECTORY = Path(__file__).resolve().parents[1] / "sandbox"
sys.path.insert(0, str(SANDBOX_DIRECTORY))
import worker as sandbox_worker  # noqa: E402


@pytest.mark.parametrize(
    "value",
    [
        "ftp://qrshield-egress-proxy:3128",
        "file:///proxy",
        "http://user:pass@qrshield-egress-proxy:3128",
        "http://",
        "not a proxy URL",
        "   ",
        "http://qrshield-egress-proxy:not-a-port",
        "http://qrshield-egress-proxy:70000",
    ],
)
def test_rejects_invalid_egress_proxy_values(monkeypatch, value):
    monkeypatch.setenv("QRSHIELD_EGRESS_PROXY", value)

    with pytest.raises(sandbox_worker.ProxyConfigurationError):
        sandbox_worker.get_egress_proxy()


def test_accepts_http_egress_proxy_without_dns_lookup(monkeypatch):
    monkeypatch.setenv("QRSHIELD_EGRESS_PROXY", "http://qrshield-egress-proxy:3128")

    assert sandbox_worker.get_egress_proxy() == "http://qrshield-egress-proxy:3128"


def test_absent_egress_proxy_fails_closed(monkeypatch):
    monkeypatch.delenv("QRSHIELD_EGRESS_PROXY", raising=False)
    monkeypatch.delenv("QRSHIELD_ALLOW_DIRECT_MODE", raising=False)

    with pytest.raises(sandbox_worker.ProxyConfigurationError):
        sandbox_worker.get_egress_proxy()


def test_worker_fails_closed_before_browser_launch_when_proxy_is_absent(monkeypatch):
    monkeypatch.delenv("QRSHIELD_EGRESS_PROXY", raising=False)
    monkeypatch.delenv("QRSHIELD_ALLOW_DIRECT_MODE", raising=False)

    emitted = []
    monkeypatch.setattr(sandbox_worker.sys, "stdin", io.StringIO('{"url":"https://example.com"}'))
    monkeypatch.setattr(sandbox_worker, "_emit", emitted.append)

    def browser_must_not_start(*_args, **_kwargs):
        raise AssertionError("Chromium must not start without the required proxy")

    monkeypatch.setattr(sandbox_worker, "_analyze_url", browser_must_not_start)

    sandbox_worker.main()

    assert emitted == [
        {
            "status": "error",
            "message": "Egress proxy configuration is invalid.",
        }
    ]


def test_explicit_development_opt_in_allows_direct_mode(monkeypatch):
    monkeypatch.delenv("QRSHIELD_EGRESS_PROXY", raising=False)
    monkeypatch.setenv("QRSHIELD_ALLOW_DIRECT_MODE", "1")

    assert sandbox_worker.get_egress_proxy() is None


@pytest.mark.parametrize(
    "url",
    ["https://example.com/resource.js", "https://cdn.example.com/image.png"],
)
@patch("sandbox.network_guard.socket.getaddrinfo")
def test_proxy_mode_allows_public_hostnames_without_worker_dns(mock_getaddrinfo, url):
    validate_request_destination(url, resolve_hostname_dns=False)

    mock_getaddrinfo.assert_not_called()


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost/x",
        "http://host.docker.internal/x",
        "http://gateway.docker.internal/x",
        "http://127.0.0.1/x",
        "http://10.0.0.1/x",
        "http://192.168.1.1/x",
        "http://169.254.169.254/x",
        "http://[::1]/x",
        "http://[fc00::1]/x",
        "http://[fe80::1]/x",
        "http://[::ffff:127.0.0.1]/x",
        "ftp://example.com/resource",
        "http://user:password@example.com/",
    ],
)
@patch("sandbox.network_guard.socket.getaddrinfo")
def test_proxy_mode_blocks_unsafe_destinations_without_dns(mock_getaddrinfo, url):
    with pytest.raises(NetworkGuardError):
        validate_request_destination(url, resolve_hostname_dns=False)

    mock_getaddrinfo.assert_not_called()


class FakeChromium:
    def __init__(self):
        self.launch_kwargs = None

    def launch(self, **kwargs):
        self.launch_kwargs = kwargs
        return object()


def test_proxy_mode_uses_official_playwright_proxy_option_without_bypass():
    chromium = FakeChromium()

    sandbox_worker._launch_browser(chromium, "http://qrshield-egress-proxy:3128")

    assert chromium.launch_kwargs == {
        "headless": True,
        "proxy": {"server": "http://qrshield-egress-proxy:3128"},
    }
    assert "bypass" not in chromium.launch_kwargs["proxy"]


def test_direct_mode_preserves_launch_without_proxy():
    chromium = FakeChromium()

    sandbox_worker._launch_browser(chromium, None)

    assert chromium.launch_kwargs == {"headless": True}
