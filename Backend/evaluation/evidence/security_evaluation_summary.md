# QRShield H1 Security and Performance Evidence

Evidence generated: 2026-08-11T20:18:18.243035+00:00

## Architecture tested

FastAPI `/scan` uses a fresh, non-root Docker worker on the internal `qrshield-worker-isolated` network. Browser traffic is sent through the persistent `qrshield-egress-proxy` on port 3128. The worker is read-only with bounded `/tmp`, CPU, memory, PID, capability, and privilege-escalation controls.

## Functional result

- Status: `success`
- Final URL: `https://example.com/`
- Title: `Example Domain`
- Risk/verdict: `10` / `Low Risk`
- VirusTotal status: `success`
- Screenshot HTTP status: `200`
- MongoDB history record present: `True`

## Isolation and proxy result

- Isolated network internal: `True`; gateway mode: `isolated`.
- Proxy running: `True`; memberships: `qrshield-proxy-egress, qrshield-worker-isolated`.
- Published proxy host ports: `False`.
- Proxy HTTPS example.com status: `200`.

## Direct-egress and private-destination result

- Worker DNS resolution: `blocked_gaierror`.
- Direct numeric TCP/443: `blocked_OSError`.
- The private-destination CSV records the expected Squid denial for loopback, private, link-local, metadata, IPv6-local, and Docker host aliases.

## Fail-closed result

- Proxy-down scan failed: `True`.
- Safe error: `Secure sandbox infrastructure is unavailable.`.
- Default-network fallback observed: `False`.
- Proxy restored running: `True`.

## Per-scan lifecycle

- Containers before: `[]`.
- Observed worker networks: `{'qrshield-scan-78541ecb-f27f-483d-955a-cc1bf20f9240': ['qrshield-worker-isolated']}`.
- Containers after: `[]`.
- Scan status: `success`.

## Test-suite result

- Passed: `121`; failed: `0`; duration: `15.614 seconds`.

## Latency summary

- Measurements: `50`; successful: `37`; failed: `13`.
- Minimum / maximum: `2.288919` / `5.346972 seconds`.
- Mean / median: `3.45260972` / `3.404471 seconds`.
- Standard deviation: `0.8486479150474893 seconds`; P90: `4.451428`; P95: `4.995195`.

## H1.6 UTF-8 portability correction

The initial benchmark intentionally remains preserved above as evidence of a Windows `cp1252`/UTF-8 subprocess decoding portability bug. Explicit UTF-8 decoding was added to the trusted Docker subprocess reads. The benchmark was repeated with the same methodology and harmless target set; the corrected run achieved 50/50 successful scans.

Corrected post-fix values: minimum `2.936825 s`, maximum `12.442203 s`, mean `4.354208 s`, median `4.221345 s`, standard deviation `1.380445 s`, P90 `4.972364 s`, and P95 `5.920358 s`. Use `latency_summary_post_utf8_fix.json` and `latency_scans_post_utf8_fix.csv` for final performance reporting.

## Remaining limitations

This evidence does not claim protection against Docker or host-kernel compromise, container escape, proxy compromise, or exfiltration to permitted public websites. Measurements are environment- and time-dependent; they are reproducibility evidence, not a formal security proof.
