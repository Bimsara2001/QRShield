# Independent Synthetic Rendered-Page / Sandbox Benchmark

This directory defines a fixed, safe H5 benchmark. `build_benchmark.py` creates
50 independently authored, inert HTML pages and freezes their checksums in
`manifest.csv` before any scoring. The historical 26 H5 development fixtures
are not inputs to this corpus and are excluded from its metrics.

`run_benchmark.py` is an explicitly opt-in controller. It does not use the
production `/scan` route because that route correctly refuses private/local
destinations and would also call MongoDB and VirusTotal. Instead, it runs the
unchanged `qrshield-sandbox-worker:latest` image on a short-lived internal
Docker network containing only:

- `h5fixtures`, a local TLS static server for these HTML files;
- `h5evalproxy`, a separate proxy that permits only `h5fixtures:8443`; and
- one disposable QRShield worker at a time, using its normal Playwright proxy
  configuration, request guard, rendered `page.content()`, and full-page PNG.

The network has no egress attachment. The worker screenshots are decoded only
to validate that Playwright created them; they are not stored in history,
MongoDB, or the normal screenshot directory. The controller tears down the
network, containers, runtime certificates, and TLS private key after the run.

## Current execution status

No benchmark result has been produced from this corpus. The initial execution
preflight reached the fixture server and proxy, but the frozen worker's
Chromium rejected the isolated local TLS CA. The base image has no NSS tooling
or offline package cache to add that CA through Chromium's normal trust
database. The benchmark must therefore remain unexecuted until that
infrastructure is supplied. This corpus and its pre-execution integrity record
are **not H5 accuracy evidence**.

The controller intentionally does not fall back to HTTP: the frozen URL engine
would add its non-HTTPS signal to every benign fixture, producing a
topology-induced false-positive rate rather than a defensible rendered-page
benchmark. It also does not disable certificate validation.

When a normal Chromium trust-store setup is available, run from `Backend`:

```powershell
venv\Scripts\python.exe evaluation\h5_rendered_benchmark\build_benchmark.py
venv\Scripts\python.exe evaluation\h5_rendered_benchmark\run_benchmark.py
```

The runner refuses to overwrite an existing `summary.json`, changes no
detector code, and applies the predeclared production binary policy: combined
score `>= 10` is phishing and a lower score is benign. It is evidence about a
synthetic rendered-page pipeline only, not live-phishing or population-level
accuracy.
