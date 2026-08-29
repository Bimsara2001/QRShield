# Independent Synthetic Offline Full-Pipeline Evaluation

This evaluation-only corpus contains 50 fixed, labelled, synthetic local HTML cases: 25 benign and 25 phishing-like. Every URL uses a reserved `.example` domain, and external-looking form/link destinations use the reserved `.invalid` domain. No fixture is fetched, served, browser-rendered, or submitted; password inputs and submit buttons are disabled and each form cancels submission.

`manifest.csv` is generated deterministically by `build_synthetic_fixtures.py`, which is the authoritative pre-evaluation case definition. The new cases are separate from the earlier H5 controlled fixtures and are not included in their results. They are independent from prior detector-tuning fixtures, but are synthetic authored material rather than an independently sourced real-world corpus.

Run from `Backend`:

```powershell
venv\Scripts\python.exe evaluation\full_pipeline\build_synthetic_fixtures.py
venv\Scripts\python.exe evaluation\full_pipeline\run_offline_evaluation.py
```

The runner verifies frozen SHA-256 values before evaluation, uses `analyze_url(url, url)` plus `detect_phishing(html, page_url=url)`, adds the scores exactly as the production scan route does, and applies the production boundaries (`10`, `70`). It does not import `main.py`, avoiding its database, VirusTotal, and sandbox dependencies. It writes the new `full_pipeline_independent_*` evidence files below `evaluation/evidence/`.

Results are labelled **Independent Synthetic Offline Full-Pipeline Evaluation**. They are not real-world phishing-accuracy claims.
