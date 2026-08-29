# H3A development/holdout methodology

H3A freezes the current `risk_engine.py` and creates a deterministic,
grouped, stratified split of the official local PhiUSIIL URL dataset.

- Seed: `2026`
- Development target: 70%
- Holdout target: 30%
- Grouping key: exact raw URL string
- Original labels: `1 = legitimate`, `0 = phishing`
- Duplicate URL groups are assigned wholly to one partition.

The holdout is locked. H3 development analysis emits only aggregate holdout
baseline metrics. It does not emit holdout error reasons, threshold sweeps,
or sample URLs. Future tuning must use development evidence only; the locked
holdout is reserved for the final H3 evaluation.

Both current binary interpretations remain frozen:

- Policy 40: score `>=40` is positive/phishing.
- Policy 70: score `>=70` is positive/phishing.

The baseline calls `analyze_url(url, url)` and performs no network access.
Redirect-dependent scoring is therefore not evaluated. H3A does not modify
production code or select new thresholds.
