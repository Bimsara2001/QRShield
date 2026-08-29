FROM ubuntu/squid:6.6-24.04_beta@sha256:6a097f68bae708cedbabd6188d68c7e2e7a38cedd05a176e1cc0ba29e3bbe029

# The G3D configuration imports the standalone G3C policy unchanged and only
# adds a disposable DNS server plus short DNS cache TTLs for observation.
COPY egress_proxy/squid.conf /etc/squid/squid.base.conf
COPY tests/fixtures/g3d_dns/squid.g3d.conf /etc/squid/squid.conf
