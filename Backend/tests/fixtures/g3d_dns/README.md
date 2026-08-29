# G3D controlled DNS fixture

This fixture is disposable test infrastructure. `Squid.Dockerfile` imports
the G3C `egress_proxy/squid.conf` unchanged, then sets only a controlled DNS
server and short DNS TTLs. CoreDNS serves synthetic `qrshield.test` records
from the phase-specific zone files.

`db.phase1` has public `rebind` data. `db.phase2-private` and
`db.phase2-mixed` represent changed DNS answers after TTL expiry. The
contained public test address was resolved from `example.com` before G3D:
`172.66.147.243`.

The fixture is not production DNS policy and must not be used by the
application or sandbox runner.
