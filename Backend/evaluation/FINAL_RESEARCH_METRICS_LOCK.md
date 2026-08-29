# QRShield Final Research Metrics Lock

## Scope

This is a reporting-only consolidation of frozen H3C, H5C, post-UTF-8 latency,
and H6 evidence. No detector, threshold, weight, production route, or evidence
file was changed. H3C is URL-only, H5C is controlled HTML-fixture validation,
and H6 is safe-live operational validation—not phishing-accuracy evidence.

## 1. Dataset and split methodology

| Item | Frozen record |
| --- | --- |
| Dataset/source | PhiUSIIL Phishing URL (Website), UCI ML Repository dataset 967; Prasad & Chandra (2024), DOI `10.1016/j.cose.2023.103545` |
| Source size | 235,795 rows: 100,945 label `0` phishing; 134,850 label `1` legitimate |
| Label mapping | `0 -> phishing`; `1 -> legitimate/benign` |
| Split | Deterministic grouped, stratified: seed 2026; 70% development / 30% holdout target |
| Development | 165,056 rows: 70,661 phishing; 94,395 legitimate |
| Locked holdout | 70,739 rows: 30,284 phishing; 40,455 legitimate |
| Duplicate handling | Exact raw URL grouping; 425 duplicate occurrences in 425 groups retained together; cross-partition leakage 0 |
| Holdout discipline | Locked before final evaluation, touched only for H3C final evaluation; post-holdout tuning false |

The recorded split has 235,370 unique URL groups. No row filtering is recorded
for the H3 split. PhiUSIIL is a labelled URL dataset, not a labelled
rendered-page, QR-delivery, or sandbox dataset. H3C uses offline
`analyze_url(url, url)`, so it cannot measure redirect-dependent behavior,
HTML detection, sandbox behavior, or real-world deployment prevalence.

## 2. Final URL detection metrics (H3C)

Frozen selected screening policy: **phishing if `score >= 10`**. The high-risk
UI boundary (`score >= 70`) remains separate and is not substituted here.

| Metric | Final H3C holdout value |
| --- | ---: |
| Dataset size | 70,739 |
| Phishing / legitimate | 30,284 / 40,455 |
| TP / TN / FP / FN | 25,071 / 35,992 / 4,463 / 5,213 |
| Accuracy | 0.863215 (86.32%) |
| Precision | 0.848886 (84.89%) |
| Recall / TPR | 0.827863 (82.79%) |
| Specificity / TNR | 0.889680 (88.97%) |
| False-positive rate | 0.110320 (11.03%) |
| False-negative rate | 0.172137 (17.21%) |
| F1 | 0.838243 (83.82%) |
| Balanced accuracy | 0.858771 (85.88%) |

### Confusion matrix — selected policy (`score >= 10`)

| Predicted \ Actual | Benign | Phishing |
| --- | ---: | ---: |
| Benign | 35,992 (TN) | 5,213 (FN) |
| Phishing | 4,463 (FP) | 25,071 (TP) |

For context, the frozen high-risk policy (`score >= 70`) recorded TP 234, TN
40,455, FP 0, and FN 30,050. It is not the selected H3C screening policy.

## 3. HTML detector results (H5C)

H5C is controlled fixture validation of `phishing_detector.py`; it must not be
combined with PhiUSIIL to claim a unified accuracy value.

| Controlled-fixture outcome | Count |
| --- | ---: |
| Total fixtures | 26 |
| BENIGN fixtures | 14 |
| SUSPICIOUS_CONTROLLED fixtures | 10 |
| ADDITIONAL_CONTROL fixtures | 2 |
| Fixture-specific expected outcomes passed | 26 / 26 |
| Recorded fixture expectation failures | 0 |
| Benign no-new-contextual-signal checks passed | 14 / 14 |
| Explicit suspicious-signal checks passed | 10 / 10 |

These are fixture-specific signal checks rather than binary classifier output;
therefore conventional HTML accuracy, precision, and recall are not validly
calculable. H5C limitations: no independent labelled HTML dataset; a small
manually defined credential-language list; hostname rather than eTLD+1-aware
external-form comparison; regex rather than JavaScript parsing for `eval`;
and password fields/iframes alone do not prove phishing. No active phishing
site was visited.

## 4. End-to-end latency (post-UTF-8 fix)

The frozen measurement is overall FastAPI `/scan` latency in seconds after the
UTF-8 fix: 50 successful scans over safe public targets `example.com`,
`www.wikipedia.org`, `www.python.org`, and `www.iana.org`. It is an end-to-end
safe-live operational measure, not a detector-only benchmark.

| Metric | Seconds |
| --- | ---: |
| Scans / failed scans | 50 / 0 |
| Mean | 4.354208 |
| Median | 4.221345 |
| Minimum | 2.936825 |
| Maximum | 12.442203 |
| P95 (nearest rank) | 5.920358 |
| Standard deviation | 1.380445 |

The proposal requirement of at least 50 latency cases is **COMPLETE**: exactly
50 successful scans are recorded.

## 5. Integrated operational validation (H6)

| Operational check | Frozen H6 result |
| --- | --- |
| Safe-live scans | PASS; 5 safe targets (Example.com, Google, Wikipedia, Python.org, IANA) |
| Screenshot delivery | PASS; manual verification HTTP 200, `image/png` |
| MongoDB persistence | PASS; manual verification for five safe-live scans |
| Docker worker cleanup | PASS; 0 `qrshield-scan-` workers after scanning |
| Private-target fail-closed | PASS; `POST /scan` for `http://127.0.0.1` returned `URL is not allowed for analysis.` |
| Docker infrastructure recovery | PASS |
| Backend regression suite | PASS; frozen H6 record: 162 passed |

H6 is operational evidence only and does not establish phishing-detection
accuracy, 100% detection, or real-world effectiveness.

## 6. Integrity checks

| File | Current SHA-256 | Latest frozen reference | Result |
| --- | --- | --- | --- |
| `analyzer/risk_engine.py` | `e837e453313a5507ac75f598884c929f929a08ca1a560d50a9cbc9919c1c00e1` | H6: `e837e453313a5507ac75f598884c929f929a08ca1a560d50a9cbc9919c1c00e1` | MATCH |
| `detectors/phishing_detector.py` | `1bffa7d2099ff9411bca4035334033bcee1308fec31a367d71c962f5c27a628a` | H5C/H6: `1bffa7d2099ff9411bca4035334033bcee1308fec31a367d71c962f5c27a628a` | MATCH |
| `main.py` | `409949d3d2d8858fe0dae05e731e6075bb699821644dfab2d5344edc1a185e76` | H6: `49b4c37aac0300a9c31793fd7675e8f363bd19ebdb3186ba89a3042401ab2ab4` | DIFFERENT; recorded only |

The H3C risk-engine hash (`833c39dd…`) predates the latest H6 freeze. The
current risk engine matches H6; the current phishing detector matches H5C and
H6. No unexpected protected-detector change was found. This consolidation made
no code change.

## 7. Proposal evaluation requirements

| Area | Status | Basis / outstanding work |
| --- | --- | --- |
| Frozen URL-only holdout metrics | COMPLETE | Final H3C holdout reported above. |
| Controlled HTML heuristic validation | PARTIAL | All 26 checks pass; no independent labelled HTML accuracy dataset. |
| Latency, at least 50 cases | COMPLETE | 50 post-UTF-8 safe-live `/scan` measurements. |
| Safe-live integrated validation | COMPLETE (operational) | H6 checks passed; not phishing accuracy. |
| Full rendered-page/sandbox phishing accuracy | OUTSTANDING | Needs an independently labelled, safely handled rendered-page evaluation. |
| Real-world generalizability | OUTSTANDING | Needs broader independent validation beyond PhiUSIIL and controlled fixtures. |

Overall proposal evaluation status: **PARTIAL**.

## Frozen evidence used

H3C final holdout summary/results, before/after comparison, generalization-gap,
error-summary, and policy-40/policy-70 matrices; H5C controlled validation,
H5A-to-H5B5 comparison, detector freeze, limitations, and safe-live check;
post-UTF-8 latency scans and summary; H6 integrated summary, operational
checks, and safe-live results; PhiUSIIL provenance and split manifest.
