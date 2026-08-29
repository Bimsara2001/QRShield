"""Evaluate the frozen URL and HTML detectors against local synthetic fixtures.

This runner intentionally imports only the two frozen detectors. It performs
no URL retrieval, browser/sandbox navigation, VirusTotal request, or database
operation.  A synthetic URL is used as both original and final URL, therefore
redirect-dependent scoring is intentionally not exercised.
"""

from __future__ import annotations

import csv
import hashlib
import json
import sys
from pathlib import Path


BACKEND = Path(__file__).resolve().parents[2]
ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "manifest.csv"
EVIDENCE = BACKEND / "evaluation" / "evidence"
SCREENING_THRESHOLD = 10
HIGH_RISK_THRESHOLD = 70
EXPECTED_HASHES = {
    "analyzer/risk_engine.py": "e837e453313a5507ac75f598884c929f929a08ca1a560d50a9cbc9919c1c00e1",
    "detectors/phishing_detector.py": "1bffa7d2099ff9411bca4035334033bcee1308fec31a367d71c962f5c27a628a",
}

if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from analyzer.risk_engine import analyze_url  # noqa: E402
from detectors.phishing_detector import detect_phishing  # noqa: E402
from evaluation.accuracy.metrics import metrics_from_predictions  # noqa: E402


def sha256(relative_path: str) -> str:
    return hashlib.sha256((BACKEND / relative_path).read_bytes()).hexdigest()


def verdict(score: int) -> str:
    if score >= HIGH_RISK_THRESHOLD:
        return "High Risk"
    if score >= SCREENING_THRESHOLD:
        return "Medium Risk"
    return "Low Risk"


def explanation(row: dict[str, str]) -> str:
    if row["expected_label"] == "benign":
        return "Synthetic benign page activated frozen lexical or HTML heuristics; this evaluation does not alter them."
    return "Synthetic phishing-like scenario relies on an indicator outside the frozen detector's implemented signals."


def main() -> None:
    observed_hashes = {path: sha256(path) for path in EXPECTED_HASHES}
    mismatches = {path: {"expected": EXPECTED_HASHES[path], "actual": observed_hashes[path]} for path in EXPECTED_HASHES if observed_hashes[path] != EXPECTED_HASHES[path]}
    if mismatches:
        raise SystemExit("Frozen detector hash mismatch; evaluation aborted: " + json.dumps(mismatches))

    with MANIFEST.open(newline="", encoding="utf-8") as handle:
        cases = list(csv.DictReader(handle))
    if len(cases) != 50 or {case["expected_label"] for case in cases} != {"benign", "phishing"}:
        raise SystemExit("Manifest must contain the fixed 50-case benign/phishing corpus.")

    results: list[dict[str, object]] = []
    for case in cases:
        html = (ROOT / case["local_html_fixture_path"]).read_text(encoding="utf-8")
        url_result = analyze_url(case["synthetic_url"], case["synthetic_url"])
        html_result = detect_phishing(html, page_url=case["synthetic_url"])
        combined_score = int(url_result["score"]) + int(html_result["score"])
        predicted = "phishing" if combined_score >= SCREENING_THRESHOLD else "benign"
        results.append({
            **case,
            "url_score": url_result["score"],
            "url_signals": " | ".join(url_result["reasons"]),
            "html_score": html_result["score"],
            "html_signals": " | ".join(html_result["reasons"]),
            "combined_score": combined_score,
            "predicted_label": predicted,
            "verdict": verdict(combined_score),
            "correct": str(predicted == case["expected_label"]).lower(),
        })

    labels = [str(row["expected_label"]) for row in results]
    predictions = [str(row["predicted_label"]) for row in results]
    metrics = metrics_from_predictions(labels, predictions)
    errors = []
    for result in results:
        if result["correct"] == "false":
            row = dict(result)
            row["likely_explanation"] = explanation(row)  # type: ignore[index]
            row["contributing_detector_signals"] = " | ".join(filter(None, [str(row["url_signals"]), str(row["html_signals"])])) or "None"
            errors.append(row)

    EVIDENCE.mkdir(parents=True, exist_ok=True)
    fields = ["case_id", "expected_label", "synthetic_url", "local_html_fixture_path", "rationale", "source", "url_score", "url_signals", "html_score", "html_signals", "combined_score", "predicted_label", "verdict", "correct"]
    with (EVIDENCE / "full_pipeline_independent_results.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(results)
    with (EVIDENCE / "full_pipeline_independent_errors.csv").open("w", newline="", encoding="utf-8") as handle:
        error_fields = ["case_id", "expected_label", "predicted_label", "contributing_detector_signals", "likely_explanation"]
        writer = csv.DictWriter(handle, fieldnames=error_fields)
        writer.writeheader()
        writer.writerows({field: row[field] for field in error_fields} for row in errors)
    matrix_rows = [
        {"predicted_label": "benign", "actual_benign": metrics["tn"], "actual_phishing": metrics["fn"]},
        {"predicted_label": "phishing", "actual_benign": metrics["fp"], "actual_phishing": metrics["tp"]},
    ]
    with (EVIDENCE / "full_pipeline_independent_confusion_matrix.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["predicted_label", "actual_benign", "actual_phishing"])
        writer.writeheader()
        writer.writerows(matrix_rows)
    summary = {
        "evaluation_label": "Independent Synthetic Offline Full-Pipeline Evaluation",
        "scope": "Local static fixtures evaluated with frozen analyze_url and detect_phishing only; no network, browser, sandbox, MongoDB, or VirusTotal.",
        "prediction_policy": "phishing when combined score >= 10; verdict uses production Low/Medium/High Risk boundaries 10 and 70.",
        "case_counts": {"total": len(results), "benign": labels.count("benign"), "phishing": labels.count("phishing")},
        "metrics": metrics,
        "error_case_ids": [row["case_id"] for row in errors],
        "frozen_hashes_before_and_during_evaluation": observed_hashes,
        "independence": "New fixture paths and case IDs; not drawn from or counted with H5 controlled tuning fixtures. Synthetic authorship means this is not an independently sourced real-world corpus.",
        "limitations": ["Synthetic labels and authored cases do not estimate real-world phishing prevalence or generalization.", "No browser rendering, navigation, redirect chain, screenshot, sandbox, DNS, MongoDB, or VirusTotal component is exercised.", "Synthetic URL equals final URL, so redirect-risk scoring is not evaluated.", "The benchmark is evaluation-only; detector behavior, weights, thresholds, and production scan behavior were not changed."],
    }
    (EVIDENCE / "full_pipeline_independent_summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
