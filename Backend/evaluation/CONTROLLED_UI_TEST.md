# Controlled UI Test Harness

**TEST/DEVELOPMENT ONLY — NOT A PHISHING ACCURACY BENCHMARK.**

`POST /test/controlled-scan` is an inert UI/integration harness for checking
that QRShield renders a suspicious or high-risk result end-to-end. It accepts
only the fixed `fake_banking_login` fixture ID and loads local HTML from
`evaluation/html/fixtures/`; it never accepts a request-supplied path or HTML.

The endpoint is disabled unless `QRSHIELD_ENABLE_CONTROLLED_UI_TEST=1` is set.
It does not visit a live site, invoke Playwright or the Docker sandbox, query
VirusTotal, write MongoDB history, or persist a screenshot. The rendered
preview is the existing local app logo served only at the test-only static path
`/test/static/controlled-placeholder.png`.

The default fixture is `fake_banking_login`, which is an inert H5 controlled
validation fixture. Its result must not be added to H3, H5, H6, or production
phishing-accuracy evidence.

Allowed fixture ID: `fake_banking_login`

Run the backend for an Android debug build from `Backend/`:

```powershell
$env:QRSHIELD_ENABLE_CONTROLLED_UI_TEST = "1"
uvicorn main:app --host 127.0.0.1 --port 8004
```

Unset the environment variable or restart the backend without it to disable
the harness.
