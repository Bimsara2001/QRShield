# QRShield Final Remaining-Gaps Close-Out Audit

## Scope

This audit reviewed every non-complete entry in the current proposal-compliance matrix: D2, I4, and H5. It is documentation and evidence work only. No detector, threshold, weight, keyword list, risk score, production route, or frozen evaluation result was changed. No live phishing URL was visited.

## Status before audit

| ID | Requirement | Status before | Gap classification |
| --- | --- | --- | --- |
| D2 | Graceful external-intelligence failure handling | PARTIAL | B — missing dedicated failure-acceptance evidence |
| I4 | Privacy/minimal personal-data approach | PARTIAL | C/D — missing disclosure plus actual retention, access-control, and credential-management gaps |
| H5 | Labelled rendered-page/sandbox phishing-accuracy benchmark | OUTSTANDING | B — genuine evaluation gap |

## D2 — external-intelligence failure handling

`threat_intel/virustotal.py` returns a structured error object for non-200 responses and request exceptions. `main.py` carries that object in the scan response and history record rather than treating it as a scan failure.

A controlled no-network acceptance check replaced `requests.get` before calling the VirusTotal helper. It confirmed that a non-200 response and a request exception both return structured error objects. A controlled `/scan` execution with a structured VirusTotal error completed successfully, returned `virustotal.status = error`, and invoked persistence once. This result is preserved in `evidence/external_intelligence_failure_handling_evidence.json`.

Decision: **COMPLETE**. The narrow requirement is met by the existing implementation and controlled acceptance evidence. This does not claim retry behavior, third-party availability, or sanitization of exception-detail text.

## I4 — privacy/minimal personal-data approach

The evidence document `PRIVACY_AND_DATA_HANDLING_EVIDENCE.md` records the current data path. The application explicitly accepts a URL and stores successful scan results including URLs, title, screenshot URL, risk result, reasons, and VirusTotal result. It has no separate name/email field in the inspected route, but URLs and screenshots can contain sensitive information.

The Clear History UI deletes MongoDB history documents only. It does not remove successful screenshot files. No retention period, authentication/authorization for history or screenshots, log-retention/redaction policy, privacy notice, or user-facing disclosure of VirusTotal transmission is evidenced. Hard-coded service credentials were found in tracked source; their values are not reproduced in audit evidence.

Decision: **PARTIAL**. The gap is not documentation only, so new documentation cannot close it. The smallest closure work is an implemented and verified retention/deletion and access-control model, including secret rotation/configuration and accurate user disclosure.

## H5 — labelled rendered-page/sandbox accuracy benchmark

H5C performed 26 predefined controlled HTML-fixture checks after the H5B1–H5B5 development progression. The H5 report explicitly records that it is controlled heuristic validation, not real-world phishing accuracy, and that no independent labelled HTML corpus was evaluated. The fixture history shows these controls were used during detector development; they cannot be relabelled as an independent benchmark.

The later 50-case Independent Synthetic Offline Full-Pipeline Evaluation is separate from the H5 fixtures and used frozen hashes. It complements H5 by providing fixed labelled synthetic static cases, but its documented scope excludes browser rendering, navigation, sandbox, redirects, screenshots, MongoDB, and VirusTotal. It therefore cannot satisfy the specific H5 requirement for a labelled rendered-page/sandbox accuracy benchmark or rewrite historical H5 results. C4 separately remains complete for controlled HTML validation.

Decision: **OUTSTANDING**. The minimum next action is to collect or construct a safely handled, independently labelled rendered-page corpus and evaluate the frozen browser/sandbox workflow without tuning. If the proposal is amended to require only controlled HTML validation, that is a proposal wording/claim-boundary decision rather than evidence that the current H5 requirement is fulfilled.

## Final evidence integrity check

The existing evidence still records the following separate results: H3C N=70,739, accuracy 86.32%, precision 84.89%, recall 82.79%, F1 83.82%; independent synthetic full-pipeline N=50, accuracy 82.00%, F1 82.35%; external generalizability N=20,000, accuracy 82.14%, F1 80.46%; safe-live latency 50 successful scans, mean 4.354 s, median 4.221 s, p95 5.920 s; and usability N=5, task success 100.00%, easy completion 95.56%, Nielsen mean 4.92/5, QRShield experience mean 4.94/5.

## Status after audit

| ID | Status after | Reason |
| --- | --- | --- |
| D2 | COMPLETE | Existing fallback behavior passed controlled no-network acceptance checks. |
| I4 | PARTIAL | Evidence reveals unresolved implementation and disclosure gaps. |
| H5 | OUTSTANDING | No independent labelled rendered-page/sandbox benchmark exists. |

The overall proposal remains **PARTIAL**: **40 COMPLETE, 1 PARTIAL, 0 IN PROGRESS, 1 OUTSTANDING**.

## Required next action

The highest-priority next action is to address I4 with an implemented, verified data-handling design: rotate/remove hard-coded credentials, enforce screenshot-aware retention/deletion, restrict history/screenshot access, and disclose storage and external transmission accurately. H5 remains a separate benchmark-evaluation requirement if that claim is needed.
