# H6 Final Integrated-System Evaluation

H6 freezes the final post-`www`-redirect-precision system state. It is a small, safe operational integration evaluation, not a phishing-accuracy benchmark. No production detection logic, thresholds, sandbox/security behavior, VirusTotal behavior, MongoDB behavior, API behavior, or Flutter behavior was changed for this evidence run.

## Frozen state

| Component | SHA-256 |
| --- | --- |
| `Backend/analyzer/risk_engine.py` | `e837e453313a5507ac75f598884c929f929a08ca1a560d50a9cbc9919c1c00e1` |
| `Backend/detectors/phishing_detector.py` | `1bffa7d2099ff9411bca4035334033bcee1308fec31a367d71c962f5c27a628a` |
| `Backend/main.py` | `49b4c37aac0300a9c31793fd7675e8f363bd19ebdb3186ba89a3042401ab2ab4` |

- `SCREENING_THRESHOLD = 10`
- `HIGH_RISK_THRESHOLD = 70`
- The H5C phishing-detector hash matches its expected frozen hash.
- Redirect-risk comparison treats only conventional leading `www.` canonicalization as equivalent; arbitrary subdomains remain significant.

## Safe-live checks — PASS

All five safe URLs returned `success`, score `0`, `Low Risk`, empty reasons, and VirusTotal `success`:

| Input | Final URL |
| --- | --- |
| `https://example.com` | `https://example.com/` |
| `https://google.com` | `https://www.google.com/` |
| `https://www.wikipedia.org` | `https://www.wikipedia.org/` |
| `https://www.python.org` | `https://www.python.org/` |
| `https://www.iana.org` | `https://www.iana.org/` |

Google’s former `www` canonical redirect false positive was removed by the pre-H6 precision fix.

## Operational checks — PASS

- Screenshots were manually verified through the active port-8004 API with HTTP `200` and `Content-Type: image/png`. Observed sizes were: example.com `15,909` bytes; wikipedia.org `190,003` bytes; python.org `396,997` bytes; iana.org `106,530` bytes. Google’s screenshot size was not recorded and is not claimed.
- MongoDB persistence was manually confirmed for Google, Example.com, Wikipedia, Python.org, and IANA. This is operational verification, not an automated database test.
- `docker ps -a --filter "name=qrshield-scan-"` found no scan workers after testing: ephemeral worker cleanup **PASS**. `qrshield-egress-proxy` remained the persistent infrastructure component.
- The private-target request `POST /scan` with `{"url":"http://127.0.0.1"}` returned `{"status":"error","message":"URL is not allowed for analysis."}`. No further unsafe targets were attempted.
- The Docker Desktop outage after WSL shutdown was diagnosed as unavailable Docker infrastructure, not a detector failure. After restart, both required networks existed, the proxy was running, and a direct `run_sandbox(example.com)` succeeded. The outage is not counted as a detection-accuracy failure.

## Regression suite — PASS

`venv\\Scripts\\python.exe -m pytest tests -q -p no:cacheprovider` completed with **162 passed**.

## Limitations

- No active phishing URLs were visited for H6, and H6 does not establish 100% phishing detection or perfect security.
- H3C remains the frozen URL-only labelled holdout accuracy evaluation; H5C remains controlled HTML heuristic validation.
- VirusTotal is supplementary intelligence, not ground truth.
- The backend still emits screenshot URLs using `localhost:8000`; Flutter currently normalizes backend asset URLs for the configured development backend. This is an environment/configuration limitation and was intentionally not changed during H6.
- The H6 sample is intentionally small and safe.

Detailed machine-readable evidence is in `evaluation/evidence/h6_final_integrated_summary.json`, `evaluation/evidence/h6_safe_live_results.csv`, and `evaluation/evidence/h6_operational_checks.json`.
