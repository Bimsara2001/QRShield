# QRShield controlled egress proxy (G3C)

This directory contains the standalone Squid forward-proxy image used for
G3C functional and ACL validation. It is not integrated with QRShield's
FastAPI application, sandbox runner, or Playwright worker.

The configuration intentionally permits clients only from the disposable
`172.30.0.0/24` isolated test network and permits destination ports 80 and
443 only. It disables response caching and Squid access logging.

G3C validates basic HTTP/HTTPS forwarding and literal/local destination
denials. It does not establish mixed-DNS-answer handling, DNS-rebinding
protection, final proxy runtime hardening, or production runner integration.
