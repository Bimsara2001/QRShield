"""Final, one-time H3 evaluation of the locked PhiUSIIL holdout partition."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import statistics
from collections import Counter
from pathlib import Path

from analyzer.risk_engine import analyze_url
from .metrics import calculate_metrics


EXPECTED_RISK_ENGINE_SHA256 = "833c39dd75979be8413e9833723a5e55ea337338108f70875f97c089bf898485"
SCREENING_THRESHOLD = 10
HIGH_RISK_THRESHOLD = 70
EXPECTED_HOLDOUT_ROWS = 70739
EXPECTED_BENIGN = 40455
EXPECTED_PHISHING = 30284


def _metrics(labels: list[str], scores: list[int], threshold: int) -> dict[str, object]:
    positive = [score >= threshold for score in scores]
    result = calculate_metrics(
        tp=sum(label == "phishing" and pred for label, pred in zip(labels, positive)),
        tn=sum(label == "benign" and not pred for label, pred in zip(labels, positive)),
        fp=sum(label == "benign" and pred for label, pred in zip(labels, positive)),
        fn=sum(label == "phishing" and not pred for label, pred in zip(labels, positive)),
    )
    result["balanced_accuracy"] = (result["recall"] + result["specificity"]) / 2
    return result


def _bands(scores: list[int]) -> dict[str, int]:
    return {
        "0": sum(score == 0 for score in scores),
        "1_9": sum(1 <= score <= 9 for score in scores),
        "10_19": sum(10 <= score <= 19 for score in scores),
        "20_29": sum(20 <= score <= 29 for score in scores),
        "30_39": sum(30 <= score <= 39 for score in scores),
        "40_69": sum(40 <= score <= 69 for score in scores),
        "70_plus": sum(score >= 70 for score in scores),
    }


def _distribution(scores: list[int]) -> dict[str, object]:
    return {
        "count": len(scores),
        "mean": statistics.mean(scores) if scores else None,
        "median": statistics.median(scores) if scores else None,
        "minimum": min(scores) if scores else None,
        "maximum": max(scores) if scores else None,
        "bands": _bands(scores),
    }


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def evaluate(dataset: Path, manifest: Path, evidence_dir: Path, accuracy_dir: Path) -> dict[str, object]:
    root = Path(__file__).resolve().parents[2]
    risk_engine_path = root / "analyzer" / "risk_engine.py"
    risk_hash = hashlib.sha256(risk_engine_path.read_bytes()).hexdigest()
    if risk_hash != EXPECTED_RISK_ENGINE_SHA256:
        raise RuntimeError(f"Final risk_engine hash mismatch: {risk_hash}")
    main_hash = hashlib.sha256((root / "main.py").read_bytes()).hexdigest()

    partitions: dict[int, str] = {}
    with manifest.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            partitions[int(row["row_number"])] = row["partition"]

    labels: list[str] = []
    scores: list[int] = []
    results: list[dict[str, object]] = []
    reason_fp = Counter()
    reason_fn = Counter()
    fp_samples: list[dict[str, object]] = []
    fn_samples: list[dict[str, object]] = []

    with dataset.open(newline="", encoding="utf-8-sig") as handle:
        for row_number, row in enumerate(csv.DictReader(handle), 1):
            if partitions[row_number] != "holdout":
                continue
            url = (row.get("URL") or "").strip()
            label = "benign" if row["label"] == "1" else "phishing"
            analysis = analyze_url(url, url)
            score = int(analysis["score"])
            reasons = list(analysis.get("reasons", []))
            policy10 = "phishing" if score >= SCREENING_THRESHOLD else "benign"
            policy70 = "phishing" if score >= HIGH_RISK_THRESHOLD else "benign"
            sample = {
                "sample_id": f"phiusiil-holdout-{row_number:06d}",
                "url_sha256": hashlib.sha256(url.encode("utf-8")).hexdigest(),
                "original_dataset_label": int(row["label"]),
                "ground_truth": label,
                "risk_score": score,
                "verdict": "High Risk" if score >= HIGH_RISK_THRESHOLD else "Medium Risk" if score >= SCREENING_THRESHOLD else "Low Risk",
                "predicted_policy_10": policy10,
                "predicted_policy_70": policy70,
                "reasons": " | ".join(reasons),
            }
            labels.append(label)
            scores.append(score)
            results.append(sample)
            if label == "benign" and policy10 == "phishing":
                for reason in reasons:
                    reason_fp[reason] += 1
                if len(fp_samples) < 20:
                    fp_samples.append({key: sample[key] for key in ("sample_id", "url_sha256", "risk_score", "reasons")})
            if label == "phishing" and policy10 == "benign":
                for reason in reasons:
                    reason_fn[reason] += 1
                if len(fn_samples) < 20:
                    fn_samples.append({key: sample[key] for key in ("sample_id", "url_sha256", "risk_score", "reasons")})

    class_counts = {"benign": labels.count("benign"), "phishing": labels.count("phishing")}
    if len(labels) != EXPECTED_HOLDOUT_ROWS or class_counts != {"benign": EXPECTED_BENIGN, "phishing": EXPECTED_PHISHING}:
        raise RuntimeError(f"Unexpected locked holdout shape: rows={len(labels)}, classes={class_counts}")

    final_metrics = {
        "policy_10": _metrics(labels, scores, SCREENING_THRESHOLD),
        "policy_70": _metrics(labels, scores, HIGH_RISK_THRESHOLD),
    }
    baseline = json.loads((evidence_dir / "phiusiil_holdout_baseline_locked.json").read_text(encoding="utf-8"))["policies"]
    comparison = []
    metric_names = ("accuracy", "precision", "recall", "f1", "specificity", "false_positive_rate", "false_negative_rate", "balanced_accuracy")
    for metric in metric_names:
        before = baseline["policy_40"][metric]
        after = final_metrics["policy_10"][metric]
        comparison.append({"metric": metric, "baseline_threshold": 40, "final_threshold": 10, "baseline": before, "final": after, "absolute_change": after - before, "percentage_point_change": (after - before) * 100})

    dev = json.loads((evidence_dir / "phiusiil_h3b2_development_metrics.json").read_text(encoding="utf-8"))["selected_threshold"]
    generalization = []
    for metric in ("precision", "recall", "f1", "false_positive_rate", "balanced_accuracy"):
        generalization.append({"metric": metric, "development": dev[metric], "holdout": final_metrics["policy_10"][metric], "holdout_minus_development": final_metrics["policy_10"][metric] - dev[metric]})

    evidence_dir.mkdir(parents=True, exist_ok=True)
    with (evidence_dir / "phiusiil_h3c_final_holdout_results.csv").open("w", newline="", encoding="utf-8") as handle:
        fields = list(results[0])
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(results)
    with (evidence_dir / "phiusiil_h3c_before_after_comparison.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(comparison[0]))
        writer.writeheader()
        writer.writerows(comparison)

    distributions = {label: _distribution([score for score, actual in zip(scores, labels) if actual == label]) for label in ("benign", "phishing")}
    _write_json(evidence_dir / "phiusiil_h3c_score_distribution.json", distributions)
    _write_json(evidence_dir / "phiusiil_h3c_error_summary.json", {
        "policy": "score >= 10",
        "false_positive_count": final_metrics["policy_10"]["fp"],
        "false_negative_count": final_metrics["policy_10"]["fn"],
        "false_positive_reasons": dict(reason_fp.most_common()),
        "false_negative_reasons": dict(reason_fn.most_common()),
        "false_positive_samples_redacted": fp_samples,
        "false_negative_samples_redacted": fn_samples,
    })
    _write_json(evidence_dir / "phiusiil_h3c_generalization_gap.json", {"development_threshold": 10, "metrics": generalization})

    summary = {
        "experiment": "H3C FINAL HOLDOUT EVALUATION",
        "holdout_locked_before_evaluation": True,
        "holdout_touched_only_for_final_evaluation": True,
        "post_holdout_tuning": False,
        "rows": len(labels),
        "class_counts": class_counts,
        "cross_partition_duplicate_leakage": 0,
        "url_only_method": "analyze_url(url, url); no network access",
        "risk_engine_sha256": risk_hash,
        "main_py_sha256": main_hash,
        "screening_threshold": SCREENING_THRESHOLD,
        "high_risk_threshold": HIGH_RISK_THRESHOLD,
        "final_metrics": final_metrics,
        "baseline_policy_40": baseline["policy_40"],
        "baseline_policy_70": baseline["policy_70"],
        "generalization_gap": generalization,
        "limitations": ["URL-only evaluation; redirect-dependent behavior is unavailable because original_url equals final_url.", "This is not a full webpage/sandbox detection accuracy evaluation."],
    }
    _write_json(evidence_dir / "phiusiil_h3c_final_holdout_summary.json", summary)

    accuracy_dir.mkdir(parents=True, exist_ok=True)
    policy10 = final_metrics["policy_10"]
    policy70 = final_metrics["policy_70"]
    markdown = f"""# H3 Final Holdout Evaluation\n\nThis is the first and final evaluation of the locked H3 holdout. No tuning or production changes were performed after these results.\n\n## Final algorithm\n\n- `risk_engine.py` SHA-256: `{risk_hash}`\n- `main.py` SHA-256: `{main_hash}`\n- Screening threshold: `score >= 10`\n- High Risk threshold: `score >= 70`\n- Method: offline `analyze_url(url, url)`; no network access.\n\n## Holdout\n\n- Rows: **{len(labels):,}**\n- Benign: **{class_counts['benign']:,}**\n- Phishing: **{class_counts['phishing']:,}**\n- Cross-partition duplicate leakage: **0**\n\n## Final screening policy (threshold 10)\n\nTP **{policy10['tp']:,}**, TN **{policy10['tn']:,}**, FP **{policy10['fp']:,}**, FN **{policy10['fn']:,}**\n\nAccuracy **{policy10['accuracy']:.4f}**, precision **{policy10['precision']:.4f}**, recall **{policy10['recall']:.4f}**, F1 **{policy10['f1']:.4f}**, specificity **{policy10['specificity']:.4f}**, FPR **{policy10['false_positive_rate']:.4f}**, FNR **{policy10['false_negative_rate']:.4f}**, balanced accuracy **{policy10['balanced_accuracy']:.4f}**.\n\n## High Risk policy (threshold 70)\n\nTP **{policy70['tp']:,}**, TN **{policy70['tn']:,}**, FP **{policy70['fp']:,}**, FN **{policy70['fn']:,}**, F1 **{policy70['f1']:.4f}**, recall **{policy70['recall']:.4f}**.\n\n## Limitations\n\nH3 measures the URL lexical detector only. It does not measure full rendered webpage or sandbox detection accuracy. Redirect scoring is not evaluated because the URL is passed as both original and final URL.\n"""
    (accuracy_dir / "H3_FINAL_EVALUATION.md").write_text(markdown, encoding="utf-8")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--accuracy-dir", type=Path, required=True)
    args = parser.parse_args()
    summary = evaluate(args.dataset.resolve(), args.manifest.resolve(), args.evidence_dir.resolve(), args.accuracy_dir.resolve())
    print(json.dumps({"rows": summary["rows"], "class_counts": summary["class_counts"], "risk_engine_sha256": summary["risk_engine_sha256"], "post_holdout_tuning": summary["post_holdout_tuning"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
