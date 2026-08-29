import socket
from unittest.mock import patch

import pytest

from security.url_validator import URLValidationError, validate_public_url


PUBLIC_V4 = "93.184.216.34"
PUBLIC_V6 = "2606:2800:220:1:248:1893:25c8:1946"


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
        "http://localhost",
        "http://localhost:8000",
        "http://LOCALHOST.",
        "http://subdomain.localhost",
        "http://127.0.0.1",
        "http://127.1",
        "http://0.0.0.0",
        "http://10.0.0.1",
        "http://172.16.0.1",
        "http://172.31.255.255",
        "http://192.168.1.1",
        "http://169.254.169.254",
        "http://[::1]",
        "http://[fe80::1]",
        "http://[fc00::1]",
        "http://[::ffff:127.0.0.1]",
        "file:///etc/passwd",
        "ftp://example.com",
        "javascript:alert(1)",
        "data:text/plain,test",
        "not a valid url",
        "http:///missing-host",
        "http://user:password@example.com",
        "http://example.com:65536",
    ],
)
def test_rejects_unsafe_or_malformed_urls(url: str) -> None:
    with pytest.raises(URLValidationError):
        validate_public_url(url)


@pytest.mark.parametrize("url", ["https://example.com", "https://www.google.com"])
@patch("security.url_validator.socket.getaddrinfo")
def test_accepts_public_hostname_urls(mock_getaddrinfo, url: str) -> None:
    mock_getaddrinfo.return_value = dns_records(PUBLIC_V4, PUBLIC_V6)

    assert validate_public_url(url) == url


@pytest.mark.parametrize("address", ["127.0.0.1", "192.168.1.20", "fe80::1234", "fc00::1234"])
@patch("security.url_validator.socket.getaddrinfo")
def test_rejects_hostname_resolving_to_non_public_address(mock_getaddrinfo, address: str) -> None:
    mock_getaddrinfo.return_value = dns_records(address)

    with pytest.raises(URLValidationError):
        validate_public_url("https://public-looking.example")


@patch("security.url_validator.socket.getaddrinfo")
def test_rejects_mixed_public_and_private_dns_answers(mock_getaddrinfo) -> None:
    mock_getaddrinfo.return_value = dns_records(PUBLIC_V4, "192.168.1.20")

    with pytest.raises(URLValidationError):
        validate_public_url("https://mixed-answer.example")


@patch("security.url_validator.socket.getaddrinfo")
def test_rejects_dns_resolution_failure(mock_getaddrinfo) -> None:
    mock_getaddrinfo.side_effect = socket.gaierror("DNS failure")

    with pytest.raises(URLValidationError, match="could not be resolved"):
        validate_public_url("https://unresolved.example")


@patch("security.url_validator.socket.getaddrinfo")
def test_preserves_path_query_and_fragment_after_validation(mock_getaddrinfo) -> None:
    mock_getaddrinfo.return_value = dns_records(PUBLIC_V4)
    url = "https://example.com:8080/path/to/page?next=%2Fhome&source=qr#details"

    assert validate_public_url(url) == url
