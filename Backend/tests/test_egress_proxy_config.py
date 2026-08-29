from pathlib import Path


CONFIG_PATH = Path(__file__).resolve().parents[1] / "egress_proxy" / "squid.conf"


def _lines():
    return [line.strip() for line in CONFIG_PATH.read_text(encoding="utf-8").splitlines()]


def _index(lines, value):
    return lines.index(value)


def test_proxy_configuration_has_required_security_controls():
    lines = _lines()
    config = "\n".join(lines)

    assert "http_port 3128" in lines
    assert "acl qrshield_workers src 172.28.240.0/24" in lines
    assert "acl Safe_ports port 80" in lines
    assert "acl Safe_ports port 443" in lines
    assert "acl SSL_ports port 443" in lines
    assert "acl CONNECT method CONNECT" in lines
    assert "localhost" in config
    assert "host.docker.internal" in config
    assert "gateway.docker.internal" in config
    assert "acl qrshield_unsafe_dst dst" in config
    assert "127.0.0.0/8" in config
    assert "169.254.0.0/16" in config
    assert "fc00::/7" in config
    assert "fe80::/10" in config
    assert "http_access deny to_localhost" in lines
    assert "http_access deny to_linklocal" in lines
    assert "pinger_enable off" in lines
    assert "cache deny all" in lines
    assert "access_log none" in lines
    assert "http_access deny all" in lines


def test_security_denies_precede_the_worker_allow_rule_and_end_with_deny_all():
    lines = _lines()
    allow_index = _index(lines, "http_access allow qrshield_workers")
    final_deny_index = _index(lines, "http_access deny all")

    for denial in (
        "http_access deny !qrshield_workers",
        "http_access deny !Safe_ports",
        "http_access deny CONNECT !SSL_ports",
        "http_access deny qrshield_local_names",
        "http_access deny to_localhost",
        "http_access deny to_linklocal",
        "http_access deny qrshield_unsafe_dst",
    ):
        assert _index(lines, denial) < allow_index

    assert allow_index < final_deny_index
    assert not any(
        line.startswith("http_access allow all") and _index(lines, line) < final_deny_index
        for line in lines
    )
