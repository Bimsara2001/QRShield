FROM coredns/coredns:1.12.1@sha256:4f7a57135719628cf2070c5e3cbde64b013e90d4c560c5ecbf14004181f91998

COPY tests/fixtures/g3d_dns/Corefile.phase1 /etc/coredns/Corefile.phase1
COPY tests/fixtures/g3d_dns/Corefile.phase2-private /etc/coredns/Corefile.phase2-private
COPY tests/fixtures/g3d_dns/Corefile.phase2-mixed /etc/coredns/Corefile.phase2-mixed
COPY tests/fixtures/g3d_dns/db.phase1 /etc/coredns/db.phase1
COPY tests/fixtures/g3d_dns/db.phase2-private /etc/coredns/db.phase2-private
COPY tests/fixtures/g3d_dns/db.phase2-mixed /etc/coredns/db.phase2-mixed

ENTRYPOINT ["/coredns"]
