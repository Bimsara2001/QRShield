# H5A HTML heuristic audit

This is an offline audit of the unchanged `detectors.phishing_detector.detect_phishing` implementation. The fixture pages are inert local HTML and are never opened by a browser or sent over the network. A neutral URL is used only to document that these results measure the HTML detector, not URL lexical scoring.

Run from `Backend/`:

```text
python evaluation/html/html_fixture_evaluator.py
```
