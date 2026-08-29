# QRShield Privacy and Data-Handling Notice

## What QRShield stores

For a successful scan, QRShield stores the submitted URL, final URL after navigation, page title, risk score, verdict, reasons, VirusTotal result when available, and a QRShield-generated screenshot reference in backend scan history. The screenshot PNG is stored by the backend to provide the destination preview and scan-history thumbnail.

QRShield does not intentionally request or store participant IDs, names, email addresses, or device identifiers as part of normal scanning. However, URLs, page titles, query strings, and screenshots can contain personal or sensitive information. Do not scan information you are not authorized to submit.

## Why the data is stored

Stored result data supports the result screen, destination preview, scan history, and summary statistics. The scan-history feature retains successful scans until the user clears history; it is not a zero-retention service.

## Screenshots and Clear History

QRShield creates screenshots with backend-generated UUID filenames. If a scan fails after a screenshot is written, QRShield removes that file. Clear History deletes stored history records and then attempts to remove the associated QRShield-owned screenshot files. Missing or invalid screenshot references do not stop history clearing; a filesystem cleanup failure can leave a screenshot that requires operator cleanup.

QRShield also removes unreferenced UUID screenshots older than 30 days by default when retention cleanup runs during a scan or history clear. The `QRSHIELD_SCREENSHOT_RETENTION_DAYS` environment variable can change that orphan-file interval. Referenced history screenshots are kept until Clear History, so active previews are not removed by age cleanup.

## External services and backend boundary

When `VIRUSTOTAL_API_KEY` is configured, QRShield sends the final URL to VirusTotal for supplementary threat intelligence. QRShield cannot control VirusTotal, infrastructure-provider, backup, or third-party retention. If VirusTotal is not configured, that optional lookup is disabled.

The browser sandbox processes the URL in a short-lived container and returns page data and a screenshot to the backend. QRShield is a research prototype with a backend deployment boundary: its sensitive scan, history, statistics, and screenshot routes require a configured application token. The Flutter application must be launched with the matching `QRSHIELD_API_TOKEN` Dart define. This is a proportionate application boundary, not enterprise identity management or a guarantee against extraction of a token from a distributed client.

## Your controls and limitations

Use **Settings → Clear History** to remove saved history and trigger associated screenshot cleanup. This does not guarantee deletion from third-party services, infrastructure logs, backups, or files that could not be removed. This notice does not claim GDPR compliance, complete anonymity, encryption at rest, or guaranteed deletion outside the QRShield backend.
