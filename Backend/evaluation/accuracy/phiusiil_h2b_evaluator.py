"""Offline H2B evaluator for the official UCI PhiUSIIL URL dataset.

Only the raw URL and original numeric label are consumed. No URL is opened,
resolved, sent to Docker, or sent to VirusTotal. The existing QRShield
``analyze_url(url, url)`` implementation is called unchanged.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import statistics
import subprocess
import time
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from analyzer.risk_engine import analyze_url

from .metrics import calculate_metrics


POLICY_THRESHOLDS = {"policy_40": 40, "policy_70": 70}
EXPECTED_LABELS = {"0", "1"}


def _nearest_rank(values: list[int], percentile: int) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, math.ceil(percentile * len(ordered) / 100) - 1)
    return ordered[index]


def _verdict(score: int) -> str:
    if score < 40:
        return "Low Risk"
    if score < 70:
        return "Medium Risk"
    return "High Risk"


def _domain(url: str) -> str:
    return urlsplit(url).hostname or "invalid-host"


def _url_hash(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()


def _git_commit(repository_root: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repository_root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            shell=False,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def _score_distribution(scores: list[int]) -> dict[str, int | float | None]:
    return {
        "count": len(scores),
        "minimum": min(scores) if scores else None,
        "maximum": max(scores) if scores else None,
        "mean": statistics.mean(scores) if scores else None,
        "median": statistics.median(scores) if scores else None,
        "standard_deviation": statistics.stdev(scores) if len(scores) > 1 else 0.0 if scores else None,
        "p25": _nearest_rank(scores, 25),
        "p75": _nearest_rank(scores, 75),
        "p90": _nearest_rank(scores, 90),
        "p95": _nearest_rank(scores, 95),
    }


def _verdict_counts(scores: list[int]) -> dict[str, int]:
    return {
        "low_risk_0_39": sum(score < 40 for score in scores),
        "medium_risk_40_69": sum(40 <= score < 70 for score in scores),
        "high_risk_70_plus": sum(score >= 70 for score in scores),
    }


def _binary_metrics(actual: list[str], scores: list[int], threshold: int) -> dict[str, object]:
    predictions = ["phishing" if score >= threshold else "benign" for score in scores]
    metrics = calculate_metrics(
        tp=sum(a == "phishing" and p == "phishing" for a, p in zip(actual, predictions)),
        tn=sum(a == "benign" and p == "benign" for a, p in zip(actual, predictions)),
        fp=sum(a == "benign" and p == "phishing" for a, p in zip(actual, predictions)),
        fn=sum(a == "phishing" and p == "benign" for a, p in zip(actual, predictions)),
    )
    metrics["balanced_accuracy"] = (metrics["recall"] + metrics["specificity"]) / 2
    return metrics


def _write_matrix(path: Path, metrics: dict[str, object]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["prediction\\ground_truth", "benign", "phishing"])
        writer.writerow(["benign", metrics["tn"], metrics["fn"]])
        writer.writerow(["phishing", metrics["fp"], metrics["tp"]])


def evaluate(dataset_path: Path, output_dir: Path) -> dict[str, object]:
    dataset_path = dataset_path.resolve()
    output_dir = output_dir.resolve()
    backend_root = Path(__file__).resolve().parents[2]
    output_dir.mkdir(parents=True, exist_ok=True)
    raw_sha256 = hashlib.sha256()
    with dataset_path.open("rb") as raw_file:
        for chunk in iter(lambda: raw_file.read(1024 * 1024), b""):
            raw_sha256.update(chunk)

    rows: list[dict[str, object]] = []
    seen_urls: set[str] = set()
    original_labels: Counter[str] = Counter()
    duplicate_count = 0
    missing_url_count = 0
    missing_label_count = 0
    malformed_url_count = 0
    unexpected_labels: Counter[str] = Counter()
    started = time.perf_counter()

    with dataset_path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or "URL" not in reader.fieldnames or "label" not in reader.fieldnames:
            raise ValueError("PhiUSIIL file must contain URL and label columns.")
        for sample_number, source_row in enumerate(reader, 1):
            url = (source_row.get("URL") or "").strip()
            numeric_label = (source_row.get("label") or "").strip()
            original_labels[numeric_label] += 1
            if not url:
                missing_url_count += 1
            if not numeric_label:
                missing_label_count += 1
            if url in seen_urls:
                duplicate_count += 1
            seen_urls.add(url)
            parsed = urlsplit(url)
            if not (parsed.scheme in {"http", "https"} and bool(parsed.hostname)):
                malformed_url_count += 1
            if numeric_label not in EXPECTED_LABELS:
                unexpected_labels[numeric_label] += 1

            record: dict[str, object] = {
                "sample_id": f"phiusiil-{sample_number:06d}",
                "domain": _domain(url),
                "url_sha256": _url_hash(url),
                "original_dataset_label": int(numeric_label) if numeric_label in EXPECTED_LABELS else numeric_label,
                "ground_truth": "benign" if numeric_label == "1" else "phishing" if numeric_label == "0" else "unsupported",
                "risk_score": None,
                "verdict": None,
                "predicted_policy_40": None,
                "predicted_policy_70": None,
                "correct_policy_40": None,
                "correct_policy_70": None,
                "reasons": [],
                "scan_status": "failed",
                "failure_category": None,
            }
            try:
                if numeric_label not in EXPECTED_LABELS:
                    raise ValueError("unexpected numeric label")
                result = analyze_url(url, url)
                score = int(result["score"])
                ground_truth = str(record["ground_truth"])
                prediction_40 = "phishing" if score >= 40 else "benign"
                prediction_70 = "phishing" if score >= 70 else "benign"
                record.update({
                    "ground_truth": ground_truth,
                    "risk_score": score,
                    "verdict": _verdict(score),
                    "predicted_policy_40": prediction_40,
                    "predicted_policy_70": prediction_70,
                    "correct_policy_40": prediction_40 == ground_truth,
                    "correct_policy_70": prediction_70 == ground_truth,
                    "reasons": result.get("reasons", []),
                    "scan_status": "success",
                })
            except Exception as exc:
                record["failure_category"] = type(exc).__name__
            rows.append(record)

    evaluation_seconds = time.perf_counter() - started
    successful = [row for row in rows if row["scan_status"] == "success"]
    actual = [str(row["ground_truth"]) for row in successful]
    scores = [int(row["risk_score"]) for row in successful]
    by_class = {
        label: [int(row["risk_score"]) for row in successful if row["ground_truth"] == label]
        for label in ("benign", "phishing")
    }
    policy_metrics = {
        name: _binary_metrics(actual, scores, threshold)
        for name, threshold in POLICY_THRESHOLDS.items()
    }

    false_positives = [
        row for row in successful
        if row["ground_truth"] == "benign" and row["predicted_policy_40"] == "phishing"
    ]
    reason_counts: Counter[str] = Counter()
    for row in false_positives:
        reason_counts.update(set(str(reason) for reason in row["reasons"]))
    false_positive_analysis = {
        "policy": "score >= 40",
        "false_positive_count": len(false_positives),
        "reasons": [
            {"reason": reason, "false_positive_count": count,
             "percentage_of_false_positives": count / len(false_positives) * 100 if false_positives else 0.0}
            for reason, count in reason_counts.most_common()
        ],
        "samples": false_positives[:20],
    }
    false_negative_analysis: dict[str, object] = {}
    for name in POLICY_THRESHOLDS:
        negatives = [
            row for row in successful
            if row["ground_truth"] == "phishing" and row[f"predicted_{name}"] == "benign"
        ]
        negative_scores = [int(row["risk_score"]) for row in negatives]
        reasons: Counter[str] = Counter()
        for row in negatives:
            reasons.update(set(str(reason) for reason in row["reasons"]))
        false_negative_analysis[name] = {
            "false_negative_count": len(negatives),
            "score_distribution": _score_distribution(negative_scores),
            "score_buckets": {
                "0": sum(score == 0 for score in negative_scores),
                "1_19": sum(1 <= score <= 19 for score in negative_scores),
                "20_39": sum(20 <= score <= 39 for score in negative_scores),
                "40_69": sum(40 <= score <= 69 for score in negative_scores),
                "70_plus": sum(score >= 70 for score in negative_scores),
            },
            "most_common_reasons": [{"reason": reason, "count": count} for reason, count in reasons.most_common()],
            "samples": negatives[:20],
        }

    sweep_rows = []
    for threshold in range(0, 101, 5):
        metrics = _binary_metrics(actual, scores, threshold)
        sweep_rows.append({"threshold": threshold, **{key: metrics[key] for key in ("precision", "recall", "f1", "false_positive_rate", "specificity")}})
    with (output_dir / "phiusiil_threshold_sweep.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(sweep_rows[0]))
        writer.writeheader()
        writer.writerows(sweep_rows)

    per_sample_fields = [
        "sample_id", "domain", "url_sha256", "original_dataset_label", "ground_truth", "risk_score", "verdict",
        "predicted_policy_40", "predicted_policy_70", "correct_policy_40", "correct_policy_70", "reasons",
        "scan_status", "failure_category",
    ]
    with (output_dir / "phiusiil_baseline_results.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=per_sample_fields)
        writer.writeheader()
        for row in rows:
            output_row = dict(row)
            output_row["reasons"] = " | ".join(str(reason) for reason in row["reasons"])
            writer.writerow(output_row)

    for name, metrics in policy_metrics.items():
        _write_matrix(output_dir / f"phiusiil_confusion_matrix_{name}.csv", metrics)
    (output_dir / "phiusiil_false_positive_analysis.json").write_text(json.dumps(false_positive_analysis, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (output_dir / "phiusiil_false_negative_analysis.json").write_text(json.dumps(false_negative_analysis, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    provenance = {
        "dataset_name": "PhiUSIIL Phishing URL (Website)",
        "source": "UCI Machine Learning Repository",
        "dataset_id": 967,
        "official_url": "https://archive.ics.uci.edu/dataset/967/phiusil-phishing-url-dataset",
        "download_url": "https://archive.ics.uci.edu/static/public/967/phiusiil%2Bphishing%2Burl%2Bdataset.zip",
        "doi": "10.1016/j.cose.2023.103545",
        "citation": "Prasad, A. & Chandra, S. (2024). PhiUSIIL Phishing URL (Website) [Dataset]. UCI Machine Learning Repository.",
        "license": "Creative Commons Attribution 4.0 International (CC BY 4.0)",
        "access_date_utc": datetime.now(UTC).date().isoformat(),
        "local_filename": dataset_path.name,
        "sha256": raw_sha256.hexdigest(),
        "original_row_count": len(rows),
        "original_legitimate_count": original_labels.get("1", 0),
        "original_phishing_count": original_labels.get("0", 0),
        "original_label_counts": dict(original_labels),
    }
    (output_dir / "phiusiil_dataset_provenance.json").write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = {
        "dataset_provenance_file": "phiusiil_dataset_provenance.json",
        "dataset_validation": {
            "columns_verified": ["URL", "label"],
            "raw_row_count": len(rows),
            "evaluated_row_count": len(successful),
            "excluded_row_count": 0,
            "missing_url_count": missing_url_count,
            "missing_label_count": missing_label_count,
            "duplicate_url_count": duplicate_count,
            "malformed_url_syntax_count": malformed_url_count,
            "unexpected_labels": dict(unexpected_labels),
        },
        "original_label_counts": dict(original_labels),
        "class_counts": {"benign": original_labels.get("1", 0), "phishing": original_labels.get("0", 0)},
        "analysis_coverage": len(successful) / len(rows) if rows else 0.0,
        "evaluation_type": "URL-only lexical risk-engine baseline",
        "network_access_used": False,
        "redirect_data_available": False,
        "redirect_feature_evaluated": False,
        "thresholds": {"policy_40_positive": "score >= 40", "policy_70_positive": "score >= 70"},
        "policies": policy_metrics,
        "score_distributions": {label: _score_distribution(scores_for_class) for label, scores_for_class in by_class.items()},
        "verdict_ranges": {label: _verdict_counts(scores_for_class) for label, scores_for_class in by_class.items()},
        "false_positive_analysis_file": "phiusiil_false_positive_analysis.json",
        "false_negative_analysis_file": "phiusiil_false_negative_analysis.json",
        "threshold_sweep_file": "phiusiil_threshold_sweep.csv",
        "offline_lexical_runtime_seconds": evaluation_seconds,
        "offline_urls_processed_per_second": len(rows) / evaluation_seconds if evaluation_seconds else None,
        "algorithm_state": {
            "git_commit": _git_commit(backend_root.parent),
            "risk_engine_sha256": hashlib.sha256((backend_root / "analyzer" / "risk_engine.py").read_bytes()).hexdigest(),
            "score_thresholds": {"low": "<40", "medium": "40-69", "high": ">=70"},
            "method": "analyze_url(url, url); original and final URL are identical because no redirect data is used",
        },
        "full_scan_evaluation": "not_run by design; PhiUSIIL phishing URLs were not visited",
    }
    (output_dir / "phiusiil_baseline_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    arguments = parser.parse_args()
    summary = evaluate(arguments.dataset, arguments.output_dir)
    print(json.dumps({
        "rows": summary["dataset_validation"]["raw_row_count"],
        "successful": summary["dataset_validation"]["evaluated_row_count"],
        "runtime_seconds": summary["offline_lexical_runtime_seconds"],
        "urls_per_second": summary["offline_urls_processed_per_second"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
