from pathlib import Path


FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "g3d_dns"


def test_g3d_squid_fixture_derives_the_existing_g3c_policy():
    dockerfile = (FIXTURE_DIR / "Squid.Dockerfile").read_text(encoding="utf-8")
    config = (FIXTURE_DIR / "squid.g3d.conf").read_text(encoding="utf-8")

    assert "COPY egress_proxy/squid.conf /etc/squid/squid.base.conf" in dockerfile
    assert "include /etc/squid/squid.base.conf" in config
    assert "dns_nameservers 172.31.0.53" in config
    assert "positive_dns_ttl 3 seconds" in config
    assert "negative_dns_ttl 1 seconds" in config


def test_g3d_dns_fixture_has_public_private_mixed_and_rebind_records():
    phase_one = (FIXTURE_DIR / "db.phase1").read_text(encoding="utf-8")
    phase_two_private = (FIXTURE_DIR / "db.phase2-private").read_text(encoding="utf-8")
    phase_two_mixed = (FIXTURE_DIR / "db.phase2-mixed").read_text(encoding="utf-8")

    assert "public-only 5 IN A 172.66.147.243" in phase_one
    assert "private-only 5 IN A 127.0.0.1" in phase_one
    assert phase_one.count("mixed-ipv4 5 IN A") == 2
    assert "mixed-ipv6 5 IN AAAA ::1" in phase_one
    assert "rebind 3 IN A 172.66.147.243" in phase_one
    assert "rebind 3 IN A 127.0.0.1" in phase_two_private
    assert "rebind-mixed 3 IN A 127.0.0.1" in phase_two_mixed
