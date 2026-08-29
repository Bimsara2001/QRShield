# H2A baseline evaluation

This package evaluates the frozen URL lexical risk engine against the
existing `Backend/evaluation_dataset.csv`. It never navigates to a URL.

The supplied source labels are `legitimate` (11) and `suspicious` (4). For
the requested binary reports only, the evaluator maps those labels to
`benign` and `phishing`, respectively. This is a declared analysis mapping,
not an independent relabelling or verification of the dataset.

Redirect-dependent scoring is not evaluated in URL-only mode: the evaluator
passes the original URL as both `url` and `final_url`, because the CSV has no
redirect ground truth. Full-site evaluation is intentionally not run; the
positive rows include synthetic/reserved/private destinations and there is no
safe historical HTML or controlled-replica corpus.

Run from `Backend/`:

```powershell
venv\Scripts\python.exe -m evaluation.accuracy.baseline_evaluator `
  --dataset evaluation_dataset.csv `
  --output-dir evaluation\evidence
```

The evaluator writes `baseline_accuracy_results.csv`,
`baseline_accuracy_summary.json`, and `baseline_algorithm_state.json`.

The large external H2B evaluator is `phiusiil_h2b_evaluator.py`. It consumes
only the official UCI PhiUSIIL `URL` and numeric `label` columns and writes
the `phiusiil_*` evidence files. Its raw CSV and ZIP are ignored by the
evaluation-data `.gitignore` because they are large local inputs.
