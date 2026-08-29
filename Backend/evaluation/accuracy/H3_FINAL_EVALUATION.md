# H3 Final Holdout Evaluation

This is the first and final evaluation of the locked H3 holdout. No tuning or production changes were performed after these results.

## Final algorithm

- `risk_engine.py` SHA-256: `833c39dd75979be8413e9833723a5e55ea337338108f70875f97c089bf898485`
- `main.py` SHA-256: `c1afbfac1c95406642d13132ae8ba3bc56f2a74127157c5e7ed04adc1d0d78d6`
- Screening threshold: `score >= 10`
- High Risk threshold: `score >= 70`
- Method: offline `analyze_url(url, url)`; no network access.

## Holdout

- Rows: **70,739**
- Benign: **40,455**
- Phishing: **30,284**
- Cross-partition duplicate leakage: **0**

## Final screening policy (threshold 10)

TP **25,071**, TN **35,992**, FP **4,463**, FN **5,213**

Accuracy **0.8632**, precision **0.8489**, recall **0.8279**, F1 **0.8382**, specificity **0.8897**, FPR **0.1103**, FNR **0.1721**, balanced accuracy **0.8588**.

## High Risk policy (threshold 70)

TP **234**, TN **40,455**, FP **0**, FN **30,050**, F1 **0.0153**, recall **0.0077**.

## Limitations

H3 measures the URL lexical detector only. It does not measure full rendered webpage or sandbox detection accuracy. Redirect scoring is not evaluated because the URL is passed as both original and final URL.
