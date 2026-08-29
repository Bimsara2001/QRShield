# QRShield Privacy and Data-Handling Evidence

## Scope and status

This document records the implemented I4 controls and their source/test evidence. It describes current QRShield behavior only. It is not a privacy policy, legal assessment, data-protection impact assessment, GDPR-compliance claim, encryption-at-rest claim, or enterprise-authentication claim.

I4 source remediation is **COMPLETE**. Credential rotation remains a required manual operational action, as recorded in `CREDENTIAL_ROTATION_REQUIRED.md`; this audit does not claim it occurred.

## Implemented controls

| Control | Implemented behavior | Evidence |
| --- | --- | --- |
| Secret management | MongoDB and VirusTotal values are read only from `MONGO_URI` and `VIRUSTOTAL_API_KEY` environment variables. | `database.py`, `threat_intel/virustotal.py`, `tests/test_privacy_controls.py` |
| Safe missing-secret behavior | Missing MongoDB configuration prevents scan-history storage and returns a safe error; missing VirusTotal configuration disables only the optional lookup. | `database.py`, `main.py`, `threat_intel/virustotal.py` |
| Git hygiene | Root `.gitignore` ignores `.env` and `.env.*` while retaining `.env.example`. | `.gitignore`, `.env.example` |
| Sensitive-route boundary | `/scan`, `/history`, `/stats`, and `/screenshots/{name}` require `X-QRShield-Api-Token`; missing configuration returns 503 and an invalid/missing token returns 401. | `main.py`, `tests/test_privacy_controls.py`, Flutter service updates |
| Screenshot access | Screenshots are served through a token-protected UUID filename route with `Cache-Control: no-store`; static-directory mounting is no longer used. | `main.py`, `tests/test_privacy_controls.py` |
| Clear History lifecycle | History records are read, deleted, then associated owned screenshots are removed only when their reference resolves to an expected UUID PNG inside the QRShield screenshot directory. | `main.py`, `tests/test_privacy_controls.py` |
| Safe cleanup | Missing files are tolerated; unsafe references are rejected; cleanup failures are counted and logged without making history deletion fail. | `main.py`, `tests/test_privacy_controls.py` |
| Orphan retention | Only unreferenced, generated UUID PNGs older than `QRSHIELD_SCREENSHOT_RETENTION_DAYS` are removed. Default: 30 days. Referenced history previews are retained. | `main.py`, `.env.example`, `tests/test_privacy_controls.py` |
| Failed-scan cleanup | A screenshot written before a later scan failure is removed. | `main.py`, `tests/test_scan_sandbox_integration.py` |
| URL-aware logging | Validation failures log only the exception type rather than the exception text; sandbox identifiers remain logged for operational diagnostics. | `main.py`, `sandbox/worker.py`, `services/sandbox_runner.py` |
| User disclosure | Settings includes a concise Privacy & Data Handling view, and the complete developer/research notice is stored in `PRIVACY_AND_DATA_HANDLING_NOTICE.md`. | `settings_screen.dart`, `PRIVACY_AND_DATA_HANDLING_NOTICE.md` |

## Data minimization and purpose

The normal scan request accepts one field: `url`. A successful history document stores the following fields because the result/history UI and statistics use them:

| Field | Purpose |
| --- | --- |
| `original_url`, `final_url` | Show the scanned and resolved destination; support history and analysis context. |
| `title` | Identify the rendered destination in results/history. |
| `screenshot` | Link the QRShield-owned preview required by result/history UI. |
| `risk_score`, `verdict`, `reasons` | Present the scan decision and explanation. |
| `virustotal` | Present supplementary external-intelligence output or disabled/error status. |

No participant usability IDs, names, emails, or device identifiers are collected by the normal scan request or stored in this document shape. This is not an anonymity claim: a URL, title, query string, screenshot, or third-party response can contain sensitive information.

## External transmission and temporary handling

The validated URL is sent to the short-lived sandbox worker for analysis. The worker returns final URL, title, HTML, and base64 screenshot data; HTML is not inserted into the successful history document. The sandbox runner uses a read-only worker, tmpfs, `--rm`, and a cleanup fallback; the worker closes browser resources. The egress proxy disables cache and access logging.

When configured, the final URL is sent to VirusTotal. The optional integration is disabled without its environment variable. QRShield makes no claim about third-party, provider, log, or backup retention.

## Remaining limitations and manual actions

- The configured application token is a shared application boundary, not per-user or enterprise authentication. The Flutter app must receive it using a non-committed Dart define; a distributed client can expose a shared token.
- Backend deployment network configuration, database access policy, encryption at rest, backups, and log sinks are outside the repository evidence.
- Clear History deletes history records and attempts associated screenshot deletion. A reported filesystem cleanup failure, backups, third-party services, or copied data can require further operator action.
- The historical MongoDB and VirusTotal credentials must be manually revoked/rotated. Source removal does not remove them from Git history or third-party systems.

## I4 decision

I4 — **Privacy/minimal personal-data approach** is **COMPLETE** for the proposal-compliance requirement: the application now has documented data minimization, source-remediated secrets, safe missing-configuration behavior, user-controlled history/screenshot deletion, bounded orphan cleanup, a proportionate sensitive-route boundary, focused tests, and an accurate disclosure. The limitations above remain binding and must not be converted into broader privacy/compliance claims.
