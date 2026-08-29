# External URL Generalizability Validation

## Dataset provenance and safety

This is an offline URL-text evaluation of the frozen QRShield URL risk engine. It combines PhishTank's `online-valid.csv` verified-online phishing feed with the fixed Tranco `38LNL` top-domain list. Only these two feed files were downloaded; no URL listed in either file was fetched, browser-opened, navigated, sent to VirusTotal, or sent to any database/service.

PhishTank rows map to `phishing`. Tranco domains are converted to `https://<domain>/` and used as a **benign proxy**, not as a guarantee that every ranked domain is benign. The exact provenance, hashes, acquisition time, raw counts, source links, and label limitations are recorded in `evaluation/evidence/external_generalization_provenance.json`.

## Hygiene and frozen policy

The runner removes malformed records and exact duplicates, checks exact URL and conservative normalized URL overlap against the locally retained full PhiUSIIL CSV, and excludes all matches. It also removes cross-class collisions. It then takes the first 10,000 eligible records from each source in source-file order, with no score-based selection.

Before scoring, it checks the frozen SHA-256 values for `analyzer/risk_engine.py` and `detectors/phishing_detector.py`. It calls only `analyze_url(url, url)` and applies the frozen H3C policy: `phishing` when score is at least `10`. No threshold, weight, keyword list, detector, or production code is changed.

## Results and comparison

### Hygiene and final sample

| Source | Raw rows | Invalid | Duplicates | PhiUSIIL overlaps | Selected |
| --- | ---: | ---: | ---: | ---: | ---: |
| PhishTank | 73,469 | 7 | 3 | 2,129 | 10,000 phishing |
| Tranco 38LNL | 1,000,000 | 0 | 0 | 18 | 10,000 legitimate-proxy |

The PhiUSIIL removals are 2,118 exact plus 29 normalized-only. Ten normalized cross-class collision keys removed 11 phishing and 10 Tranco records before selection.

### Metrics - External URL Generalizability Validation

| TP | TN | FP | FN | Accuracy | Precision | Recall | Specificity | FPR | FNR | F1 |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 7,352 | 9,076 | 924 | 2,648 | 82.14% | 88.84% | 73.52% | 90.76% | 9.24% | 26.48% | 80.46% |

| Predicted \\ Actual | Legitimate | Phishing |
| --- | ---: | ---: |
| Benign | 9,076 (TN) | 2,648 (FN) |
| Phishing | 924 (FP) | 7,352 (TP) |

The score mean/median is 17.90/15 for phishing and 1.08/0 for the legitimate proxy (all URLs: 9.49/0). Full score bands are in the summary JSON.

### H3C comparison (percentage-point difference)

| Metric | H3C | External | Difference | Direction |
| --- | ---: | ---: | ---: | --- |
| Accuracy | 86.32% | 82.14% | -4.18 | Degraded |
| Precision | 84.89% | 88.84% | +3.95 | Improved |
| Recall | 82.79% | 73.52% | -9.27 | Degraded |
| Specificity | 88.97% | 90.76% | +1.79 | Improved |
| FPR | 11.03% | 9.24% | -1.79 | Improved |
| FNR | 17.21% | 26.48% | +9.27 | Degraded |
| F1 | 83.82% | 80.46% | -3.37 | Degraded |

The 9.27-point recall/FNR difference is a material descriptive generalization gap. No statistical-significance test was performed.

### Error analysis

There are 924 false positives, mainly popular-ranked domains that activate frozen lexical/structural URL signals, and 2,648 false negatives, mainly verified phishing URLs with no or insufficient implemented lexical signals. The error file includes every error with a URL hash and safely redacted URL; no detector change followed the analysis.

The machine-readable metrics, confusion matrix, score distributions, H3C comparison, and complete redacted error records are in:

- `evaluation/evidence/external_generalization_summary.json`
- `evaluation/evidence/external_generalization_confusion_matrix.csv`
- `evaluation/evidence/external_generalization_gap.json`
- `evaluation/evidence/external_generalization_error_analysis.json`

These figures are labelled **External URL Generalizability Validation**. They must not be combined with H3C PhiUSIIL, H5 HTML, or synthetic full-pipeline results, and no statistical significance claim is made.

## Limitations

- PhishTank is a time-varying verified-online feed, so it does not establish all-phishing coverage or future performance.
- Tranco is a popularity ranking used as a legitimate proxy, not a URL-by-URL benign certification dataset.
- The balanced sample is deliberately not a real-world prevalence estimate.
- This tests URL lexical scoring only: no page content, redirects, HTML, browser/sandbox, DNS, reputation, VirusTotal, MongoDB, or live URL retrieval is included.

## Reproducibility

With the two raw source files in `evaluation/data/external_generalization/`, run:

```powershell
venv\Scripts\python.exe evaluation\external_generalization_validation.py
venv\Scripts\python.exe -m pytest tests -q -p no:cacheprovider
```

The runner writes only its new `external_generalization_*` data/evidence files. It is intentionally network-free after feed acquisition.
