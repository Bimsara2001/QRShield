# H5 Final HTML Detector Evaluation

This document records the frozen H5 HTML detector after H5B5. H5C made no production detector changes and performed no tuning.

## Frozen state

- `phishing_detector.py` SHA-256: `1bffa7d2099ff9411bca4035334033bcee1308fec31a367d71c962f5c27a628a`
- `risk_engine.py` SHA-256: `833c39dd75979be8413e9833723a5e55ea337338108f70875f97c089bf898485`
- Screening threshold: 10
- High Risk threshold: 70

## Controlled validation

The final fixture set contained 14 benign-intent fixtures, 10 suspicious controlled fixtures, and 2 additional bounded-context controls. All 26 predefined checks passed. This is controlled heuristic validation, not real-world phishing detection accuracy.

The legacy fake-banking fixture intentionally keeps its credential phrases outside the form; it therefore validates the bounded H5B5 context rule by requiring password-form-local language for the new +10 signal.

## H5 progression

- H5B1 removed the unconditional generic-form +10 signal.
- H5B2 added +10 only for password forms posting to a different hostname.
- H5B3 changed iframe detection from raw text to actual `<iframe>` structure.
- H5B4 changed eval detection from whole-document text to executable-script-scoped matching.
- H5B5 added +10 for explicit credential language inside a password form.

## Limitations

See `h5c_html_detector_limitations.json`. No active phishing URLs were visited and no independent labelled HTML corpus was evaluated.
