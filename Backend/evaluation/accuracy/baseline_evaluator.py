"""Run the frozen URL-only QRShield lexical baseline on labelled CSV data.

This evaluator never opens a destination URL. It calls the existing
``analyze_url(url, url)`` function, so redirect-dependent features are
explicitly unavailable rather than fabricated. The source dataset labels are
preserved and are only mapped for the requested binary report:
``legitimate`` -> ``benign`` and ``suspicious`` -> ``phishing``.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import statistics
import subprocess
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from analyzer.risk_engine import analyze_url

from .metrics import metrics_from_predictions


LABEL_MAP = {
    "benign": "benign",
    "legitimate": "benign",
    "phishing": "phishing",
    "suspicious": "phishing",
}
THRESHOLDS = {"policy_40": 40, "policy_70": 70}


def verdict_for_score(score: int) -> str:
    if score < 40:
        return "Low Risk"
    if score < 70:
        return "Medium Risk"
    return "High Risk"


def _domain_identifier(url: str) -> str:
    parsed = urlsplit(url)
    return parsed.hostname or "invalid-host"


def _git_commit(root: Path) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            shell=False,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return completed.stdout.strip() if completed.returncode == 0 else None


def _metrics(records: list[dict[str, object]], policy: str) -> dict[str, float | int]:
    successful = [record for record in records if record["scan_status"] == "success"]
    actual = [str(record["ground_truth"]) for record in successful]
    predicted = [str(record[policy]) for record in successful]
    if not successful:
        return {"tp": 0, "tn": 0, "fp": 0, "fn": 0, "total": 0}
    return metrics_from_predictions(actual, predicted)


def evaluate(dataset_path: Path, output_dir: Path) -> dict[str, object]:
    dataset_path = dataset_path.resolve()
    output_dir = output_dir.resolve()
    backend_root = dataset_path.parent
    records: list[dict[str, object]] = []
    source_labels: Counter[str] = Counter()
    started_at = datetime.now(UTC).isoformat()
    with dataset_path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None or not {"url", "label"}.issubset(reader.fieldnames):
            raise ValueError("Dataset must contain url,label columns.")
        for number, row in enumerate(reader, 1):
            url = (row.get("url") or "").strip()
            source_label = (row.get("label") or "").strip().lower()
            source_labels[source_label] += 1
            sample_id = f"h2-url-{number:04d}"
            ground_truth = LABEL_MAP.get(source_label)
            record: dict[str, object] = {
                "sample_id": sample_id,
                "domain": _domain_identifier(url),
                "source_label": source_label,
                "ground_truth": ground_truth or "unsupported_label",
                "risk_score": None,
                "verdict": None,
                "predicted_policy_40": None,
                "predicted_policy_70": None,
                "correct_policy_40": None,
                "correct_policy_70": None,
                "reasons": [],
                "scan_status": "failed",
                "failure_category": None,
                "latency_seconds": None,
            }
            start = time.perf_counter()
            try:
                if ground_truth is None:
                    raise ValueError("unsupported source label")
                result = analyze_url(url, url)
                score = int(result["score"])
                verdict = verdict_for_score(score)
                prediction_40 = "phishing" if score >= THRESHOLDS["policy_40"] else "benign"
                prediction_70 = "phishing" if score >= THRESHOLDS["policy_70"] else "benign"
                record.update(
                    {
                        "risk_score": score,
                        "verdict": verdict,
                        "predicted_policy_40": prediction_40,
                        "predicted_policy_70": prediction_70,
                        "correct_policy_40": prediction_40 == ground_truth,
                        "correct_policy_70": prediction_70 == ground_truth,
                        "reasons": result.get("reasons", []),
                        "scan_status": "success",
                    }
                )
            except Exception as exc:
                record["failure_category"] = type(exc).__name__
            record["latency_seconds"] = round(time.perf_counter() - start, 6)
            records.append(record)

    successful = [record for record in records if record["scan_status"] == "success"]
    scores_by_class: dict[str, list[int]] = {"benign": [], "phishing": []}
    for record in successful:
        scores_by_class[str(record["ground_truth"])].append(int(record["risk_score"]))

    def distribution(values: list[int]) -> dict[str, float | int | None]:
        return {
            "count": len(values),
            "mean": statistics.mean(values) if values else None,
            "median": statistics.median(values) if values else None,
        }

    summary: dict[str, object] = {
        "captured_at": started_at,
        "dataset": str(dataset_path),
        "dataset_size": len(records),
        "source_label_counts": dict(source_labels),
        "class_counts": dict(Counter(str(record["ground_truth"]) for record in records)),
        "successful_analyses": len(successful),
        "failed_analyses": len(records) - len(successful),
        "analysis_coverage": len(successful) / len(records) if records else 0.0,
        "evaluation_type": "URL-only lexical risk-engine baseline",
        "redirect_data_available": False,
        "redirect_feature_evaluated": False,
        "thresholds": {"policy_40_positive": "score >= 40", "policy_70_positive": "score >= 70"},
        "policies": {
            "policy_40": _metrics(records, "predicted_policy_40"),
            "policy_70": _metrics(records, "predicted_policy_70"),
        },
        "risk_score_distribution": {label: distribution(values) for label, values in scores_by_class.items()},
        "algorithm_state": {
            "git_commit": _git_commit(backend_root.parent),
            "risk_engine_sha256": hashlib.sha256(
                (backend_root / "analyzer" / "risk_engine.py").read_bytes()
            ).hexdigest(),
            "score_thresholds": {"low": "<40", "medium": "40-69", "high": ">=70"},
            "redirect_input": "final_url equals original URL because no redirect labels/data exist",
        },
        "full_scan_evaluation": "not_run; dataset contains suspicious/reserved/private destinations and no safe historical HTML corpus",
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    fields = [
        "sample_id", "domain", "source_label", "ground_truth", "risk_score", "verdict",
        "predicted_policy_40", "predicted_policy_70", "correct_policy_40", "correct_policy_70",
        "reasons", "scan_status", "failure_category", "latency_seconds",
    ]
    with (output_dir / "baseline_accuracy_results.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for record in records:
            row = dict(record)
            row["reasons"] = " | ".join(str(reason) for reason in record["reasons"])
            writer.writerow(row)
    (output_dir / "baseline_accuracy_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output_dir / "baseline_algorithm_state.json").write_text(
        json.dumps(summary["algorithm_state"], indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    arguments = parser.parse_args()
    summary = evaluate(arguments.dataset, arguments.output_dir)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
