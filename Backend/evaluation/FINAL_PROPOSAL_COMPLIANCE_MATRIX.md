# QRShield Final Proposal Compliance Matrix and Evidence Index

## Audit scope and overall status

This index records the final evidence audit and scoped I4 privacy/data-handling
implementation. It does not recompute, combine, or tune any evaluation. The
overall proposal status is **PARTIAL**: the implemented workflow, frozen URL
evaluation, controlled HTML validation, safe-live operations, synthetic
full-pipeline evaluation, external URL validation, final five-participant
usability analysis, and scoped privacy/data-handling controls have evidence. A
labelled rendered-page/sandbox accuracy benchmark remains incomplete.

Status totals: **41 COMPLETE, 0 PARTIAL, 0 IN PROGRESS, 1 OUTSTANDING**.

## Final measured results (kept separate)

| Evaluation | Dataset/class counts | TP / TN / FP / FN | Accuracy | Precision | Recall | Specificity | FPR | FNR | F1 | Scope boundary |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| H3C PhiUSIIL holdout, policy `score >= 10` | N=70,739; phishing=30,284; legitimate=40,455 | 25,071 / 35,992 / 4,463 / 5,213 | 86.32% | 84.89% | 82.79% | 88.97% | 11.03% | 17.21% | 83.82% | Frozen URL-only labelled holdout; no redirects/HTML/sandbox. |
| Independent Synthetic Offline Full-Pipeline | N=50; phishing-like=25; benign=25 | 21 / 20 / 5 / 4 | 82.00% | 80.77% | 84.00% | 80.00% | 20.00% | 16.00% | 82.35% | Authored local static fixtures; not a real-world benchmark. |
| External URL Generalizability | N=20,000; phishing=10,000; legitimate-proxy=10,000 | 7,352 / 9,076 / 924 / 2,648 | 82.14% | 88.84% | 73.52% | 90.76% | 9.24% | 26.48% | 80.46% | URL-text only; Tranco is a benign proxy, not individual certification. |

The three rows above must not be pooled into a single accuracy claim.

Latency evidence records 50 successful safe-live scans: mean **4.354 s**,
median **4.221 s**, p95 **5.920 s**. The current audit command
`venv\\Scripts\\python.exe -m pytest tests -q -p no:cacheprovider` passed
**176 tests**.

## Compliance matrix

| ID | Proposal requirement/objective | Implementation status | Evaluation status | Evidence | Final status | Notes/limitations |
| --- | --- | --- | --- | --- | --- | --- |
| A1 | QR scanning | Implemented (`MobileScanner`, QR-only format) | Source/test-level audit | `Frontend/.../lib/screens/scan_screen.dart` | COMPLETE | Device-camera usability has not been participant-tested. |
| A2 | URL extraction from scanned QR | Implemented | Source-level audit | `Frontend/.../lib/screens/scan_screen.dart` | COMPLETE | Extraction is dependent on decoded QR content. |
| A3 | Manual URL analysis | Implemented through scan API | Source-level audit | `scan_screen.dart`, `api_service.dart` | COMPLETE | Operational success depends on backend availability. |
| A4 | Risk-result presentation | Low/Medium/High result UI implemented | Source-level audit | `result_screen.dart` | COMPLETE | Visual usability still requires participant evidence. |
| B1 | Lexical/structural URL analysis | Frozen `analyze_url` implemented | Unit + H3C/external evaluation | `analyzer/risk_engine.py`, `tests/test_risk_engine.py` | COMPLETE | Lexical signals alone do not establish phishing intent. |
| B2 | Phishing/legitimate URL classification | `score >= 10` screening classification implemented | H3C and external confusion matrices | `phiusiil_h3c_final_holdout_summary.json`, `external_generalization_summary.json` | COMPLETE | This is URL classification, not webpage classification. |
| B3 | Frozen decision policy | H3C screening threshold retained | Hash-checked by tests/evaluations | `tests/test_controlled_ui_test_endpoint.py` | COMPLETE | High-Risk UI boundary (`>=70`) is separate. |
| B4 | Labelled URL holdout evaluation | Deterministic locked H3 split/evaluation present | N=70,739, metrics above | `phiusiil_h3c_final_holdout_summary.json` | COMPLETE | PhiUSIIL-specific URL-only evidence. |
| C1 | HTML phishing indicators | Detector checks configured phrase and executable-script `eval` | Unit + H5C control checks | `detectors/phishing_detector.py`, `tests/test_phishing_detector.py` | COMPLETE | Heuristics are intentionally limited. |
| C2 | Credential/password detection | Password input and form-local credential context implemented | H5C fixture checks | `h5c_html_detector_freeze.json`, `h5c_controlled_validation.csv` | COMPLETE | Password inputs are not proof of phishing. |
| C3 | Iframe/form indicators | Structural iframe and external credential-action checks implemented | H5C fixture checks | `h5c_html_detector_freeze.json` | COMPLETE | Hostname comparison is not eTLD+1-aware. |
| C4 | Controlled HTML validation | 26 predefined fixture checks passed | Controlled validation only | `H5_FINAL_EVALUATION.md`, `h5c_controlled_validation.csv` | COMPLETE | Not an independent real-world HTML accuracy estimate. |
| D1 | VirusTotal integration | Production scan invokes supplementary lookup | Integration source/test evidence | `threat_intel/virustotal.py`, `test_scan_sandbox_integration.py` | COMPLETE | Supplementary intelligence, not ground truth. |
| D2 | Graceful external-intelligence failure handling | Structured error object returned by integration | Controlled no-network checks cover non-200 and exception paths; scan continues with a VirusTotal error result | `threat_intel/virustotal.py`, `evidence/external_intelligence_failure_handling_evidence.json` | COMPLETE | Does not establish retry/availability guarantees; exception-detail sanitization is not claimed. |
| E1 | Sandbox/container isolation | Isolated Docker worker/proxy configuration implemented | Unit + H6 operational checks | `services/sandbox_runner.py`, `tests/test_sandbox_runner.py` | COMPLETE | H6 is safe-live operational evidence. |
| E2 | Private/internal destination blocking | Public-target validator and browser-time guard implemented | Unit + H6 fail-closed check | `security/url_validator.py`, `test_sandbox_network_guard.py` | COMPLETE | DNS/egress assumptions remain documented. |
| E3 | Redirect normalization/security | `www` canonicalization precision implemented | URL unit + H6 evidence | `tests/test_risk_engine.py`, `h6_precheck_www_redirect_precision.json` | COMPLETE | Meaningful redirects remain scored. |
| E4 | Ephemeral worker cleanup | Cleanup implemented | H6: zero scan workers after tests | `services/sandbox_runner.py`, `h6_operational_checks.json` | COMPLETE | Operational check is a bounded sample. |
| E5 | Screenshot isolation/delivery | PNG validation, persistence and delivery implemented | Unit + H6 manual verification | `test_scan_sandbox_integration.py`, `h6_operational_checks.json` | COMPLETE | Backend localhost asset URL limitation is documented. |
| F1 | MongoDB scan persistence | Production persistence implemented | H6 manual confirmation for five safe scans | `main.py`, `h6_operational_checks.json` | COMPLETE | Not a database durability/load benchmark. |
| F2 | Scan history | Read history endpoint and Flutter history screen implemented | Source/test-level audit | `main.py`, `history_service.dart`, `history_screen.dart` | COMPLETE | Depends on configured database. |
| F3 | History clearing | Delete history endpoint/UI client implemented | Source/test-level audit | `main.py`, `history_service.dart` | COMPLETE | No data-retention policy evidence found. |
| G1 | Dashboard | Implemented | Source-level audit | `dashboard_screen.dart` | COMPLETE | No participant usability result. |
| G2 | QR scanner screen | Implemented | Source-level audit | `scan_screen.dart`, `main.dart` | COMPLETE | No participant usability result. |
| G3 | Manual URL screen | Implemented | Source-level audit | `scan_screen.dart`, `api_service.dart` | COMPLETE | No participant usability result. |
| G4 | Result screen | Implemented | Source-level audit | `result_screen.dart` | COMPLETE | No participant usability result. |
| G5 | Destination preview | Final URL/destination information shown | Source-level audit | `result_screen.dart` | COMPLETE | Preview is informational, not a guarantee of safety. |
| G6 | History screen | Implemented | Source-level audit | `history_screen.dart` | COMPLETE | No participant usability result. |
| G7 | Settings/backend status | Implemented | Source-level audit | `settings_screen.dart`, `health_service.dart` | COMPLETE | Backend status is environment-dependent. |
| G8 | Low-Risk display | Implemented | Source-level audit | `result_screen.dart`, `history_screen.dart` | COMPLETE | UI display is not a detector-accuracy claim. |
| G9 | Controlled High-Risk display and debug/release separation | Debug-only UI control and env-gated inert endpoint implemented | Dedicated endpoint tests | `settings_screen.dart`, `api_service.dart`, `test_controlled_ui_test_endpoint.py` | COMPLETE | Test path is local/inert and is not production phishing evidence. |
| H1 | H3C size, matrix, precision/recall/specificity/FPR/FNR/F1 | Frozen H3C report present | All requested URL metrics recorded | `FINAL_RESEARCH_METRICS_LOCK.md`, `phiusiil_h3c_final_holdout_summary.json` | COMPLETE | Keep separate from other evaluations. |
| H2 | Latency >=50 scans | Safe-live scan path measured | 50/50 successful; latency above | `latency_summary_post_utf8_fix.json` | COMPLETE | Four safe public targets; not a general internet latency study. |
| H3 | Independent synthetic full-pipeline evaluation | Reproducible 50-case local corpus/runner present | Metrics and errors recorded | `full_pipeline/README.md`, `full_pipeline_independent_summary.json` | COMPLETE | Does not browser-render or exercise sandbox. |
| H4 | External generalizability validation | Reproducible PhishTank/Tranco URL-text validation present | N=20,000 with overlap removal | `EXTERNAL_GENERALIZABILITY_VALIDATION.md`, `external_generalization_summary.json` | COMPLETE | Balanced sample and benign-proxy limitations apply. |
| H5 | Labelled rendered-page/sandbox phishing-accuracy benchmark | Detector/sandbox implemented | No independent labelled rendered-page/sandbox corpus evidence | `FINAL_RESEARCH_METRICS_LOCK.md` | OUTSTANDING | Do not infer it from synthetic static HTML or H6. |
| H6 | Nielsen 10-heuristic usability study, >=5 participants | Final anonymized Google Forms responses imported | Five valid participants completed T1Ã¢â‚¬â€œT9; all ten Nielsen items analyzed and preserved | `FINAL_USABILITY_EVALUATION.md`, `evidence/usability/final_usability_summary.json` | COMPLETE | Controlled N=5 convenience/usability sample; descriptive and not population-generalizable. |
| I1 | No intentional live-phishing browsing during controlled evaluation | Safe evaluation procedures documented | H5/H6/full-pipeline/external safety statements | `H5_FINAL_EVALUATION.md`, `H6_FINAL_INTEGRATED_EVALUATION.md` | COMPLETE | External feed download did not fetch listed URLs. |
| I2 | Synthetic/local phishing fixtures | Inert local fixtures and allowlisted control exist | H5/full-pipeline evidence | `evaluation/html/fixtures/`, `evaluation/full_pipeline/` | COMPLETE | Synthetic fixtures are non-operational. |
| I3 | Redacted external error evidence where appropriate | Error analysis uses redacted URLs plus hashes | All external errors recorded | `external_generalization_error_analysis.json` | COMPLETE | Full local result manifest is retained for reproducibility. |
| I4 | Privacy/minimal personal-data approach | Environment-only service configuration, token-protected sensitive routes, safe screenshot lifecycle, user controls, and disclosure implemented | Focused privacy tests cover missing optional secret, token guard, screenshot access, Clear History cleanup, traversal rejection, cleanup failure, retention, and source-secret absence | `PRIVACY_AND_DATA_HANDLING_EVIDENCE.md`, `PRIVACY_AND_DATA_HANDLING_NOTICE.md`, `evidence/privacy/data_handling_evidence.json`, `tests/test_privacy_controls.py` | COMPLETE | Shared-token boundary is not enterprise authentication; historical credential rotation remains a required manual operational action. |
| I5 | Documented limitations | Evaluation and operational limits documented | H3/H5/H6/full-pipeline/external reports | `FINAL_RESEARCH_METRICS_LOCK.md`, `EXTERNAL_GENERALIZABILITY_VALIDATION.md` | COMPLETE | Limitations constrain all performance claims. |

## Evidence index

| Evidence/report | Purpose and objective supported | Key result | Frozen/final | Limitations |
| --- | --- | --- | --- | --- |
| `FINAL_RESEARCH_METRICS_LOCK.md` | Consolidates H3C, H5C, latency, H6 | Frozen scope/claim boundaries | Final consolidation | Predates new synthetic/external reports. |
| `evidence/phiusiil_h3c_final_holdout_summary.json` | H3C URL holdout | N=70,739; policy-10 metrics above | Frozen final | URL-only. |
| `html/H5_FINAL_EVALUATION.md` and `evidence/h5c_controlled_validation.csv` | HTML heuristic controls | 26/26 predefined checks pass | Frozen H5C | Not independent accuracy. |
| `H6_FINAL_INTEGRATED_EVALUATION.md` and `evidence/h6_operational_checks.json` | Safe-live integration/security | Five safe scans; worker cleanup, screenshot, persistence, private-target checks pass | Frozen H6 | Not phishing accuracy. |
| `evidence/latency_summary_post_utf8_fix.json` | End-to-end safe-live latency | 50 successful scans; mean 4.354 s; p95 5.920 s | Frozen measurement | Limited safe targets/environment. |
| `tests/test_controlled_ui_test_endpoint.py` | Inert High-Risk UI control and source integrity | Debug/env-gated, no sandbox/VT/MongoDB in control path | Current regression test | Not user-study evidence. |
| `tests/test_sandbox_network_guard.py`, `test_url_validator.py`, `test_sandbox_runner.py` | SSRF/egress/container safety | Private, mixed DNS, and unsafe routes are blocked; hardening tested | Current regression tests | Tests are not a formal security certification. |
| `full_pipeline/README.md` and `evidence/full_pipeline_independent_summary.json` | Independent synthetic pipeline evaluation | N=50; metrics above | Current reproducible evaluation | Static synthetic inputs only. |
| `EXTERNAL_GENERALIZABILITY_VALIDATION.md` and `evidence/external_generalization_*.json` | Independent external URL validation | N=20,000; metrics and H3C gap recorded | Current reproducible evaluation | PhishTank time variance; Tranco proxy labels. |
| `FINAL_USABILITY_EVALUATION.md` and `evidence/usability/` | Final H6 usability evaluation | N=5; 100.00% task success; Nielsen mean 4.92/5 | Final derived evidence | Controlled, self-reported convenience/usability sample; not statistically generalizable. |
| `evidence/external_intelligence_failure_handling_evidence.json` | D2 fallback acceptance | Structured error paths and scan continuation passed without network access | Current controlled audit | No availability/retry/sanitization assurance. |
| `PRIVACY_AND_DATA_HANDLING_EVIDENCE.md`, `PRIVACY_AND_DATA_HANDLING_NOTICE.md`, and `evidence/privacy/data_handling_evidence.json` | I4 privacy/data-handling controls | Environment-only secrets, protected routes, safe history/screenshot cleanup, orphan retention, disclosure | Current source/test audit | Not a privacy policy, legal-compliance, or enterprise-authentication claim; manual credential rotation remains required. |
| `FINAL_REMAINING_GAPS_AUDIT.md` and `evidence/final_remaining_gaps_audit.json` | Pre-I4-implementation close-out decision for D2, I4, H5 | D2 complete; I4 partial at that audit point; H5 outstanding | Historical audit | Superseded for I4 by the current privacy-control evidence; no detector or frozen-evidence change. |
| `tests/` | Current backend regression suite | 176 passed after privacy-control tests | Current audit | Does not replace user/field evaluation. |

## Remaining work

- **P1 — If a full rendered-page/sandbox accuracy claim is desired, collect an independently labelled, safely handled rendered-page corpus and evaluate it without tuning.** Current synthetic static fixtures and H6 cannot support that claim.

## Research claim boundaries

### QRShield can claim

- Measured frozen H3C URL-only holdout performance under `score >= 10`.
- Measured external URL-text generalizability performance on the documented balanced PhishTank/Tranco sample.
- Measured local, synthetic offline full-pipeline-function performance on 50 fixtures.
- Measured safe-live latency on 50 scans and bounded H6 operational/security checks.
- Observed task completion and self-reported usability ratings in the documented controlled N=5 usability evaluation.
- Implemented and tested an inert, debug-gated High-Risk UI path and current 169-test regression result.

### QRShield cannot claim

- 100% phishing detection, zero false positives, or statistical significance not actually tested.
- Real-world full-pipeline/sandbox accuracy equal to the synthetic offline evaluation.
- That Tranco domains are individually certified benign or that the balanced external sample represents real-world prevalence.
- Population-generalizable usability, a general privacy compliance program, or a formal security certification.

## Integrity

Current SHA-256 values match the required frozen detector references:

- `analyzer/risk_engine.py`: `e837e453313a5507ac75f598884c929f929a08ca1a560d50a9cbc9919c1c00e1`
- `detectors/phishing_detector.py`: `1bffa7d2099ff9411bca4035334033bcee1308fec31a367d71c962f5c27a628a`

Privacy/configuration/history/screenshot code was changed for I4. No detector logic, threshold, weight, keyword list, scoring behavior, or frozen prior evidence file was changed.
