"""Development-only screening-threshold calibration for H3B2.

This module deliberately reads only rows assigned to the H3 development
partition.  It never emits holdout samples or holdout metrics.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import time
from pathlib import Path

from analyzer.risk_engine import analyze_url

from .metrics import calculate_metrics


H3B1_RISK_ENGINE_SHA256 = (
    "121b64d4826f01f604b75a1ac15e1aef1a6b492e2b5e80f29c3ffdeba2dbefa6"
)
CURRENT_SCREENING_THRESHOLD = 40
HIGH_RISK_THRESHOLD = 70
CALIBRATION_MIN_THRESHOLD = 1
CALIBRATION_MAX_THRESHOLD = 40


def _load_development_scores(dataset_path: Path, manifest_path: Path) -> tuple[list[str], list[int]]:
    manifest: dict[int, str] = {}
    with manifest_path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            manifest[int(row["row_number"])] = row["partition"]

    labels: list[str] = []
    scores: list[int] = []
    with dataset_path.open(newline="", encoding="utf-8-sig") as handle:
        for row_number, row in enumerate(csv.DictReader(handle), 1):
            if manifest[row_number] != "development":
                continue
            url = (row.get("URL") or "").strip()
            labels.append("benign" if row["label"] == "1" else "phishing")
            scores.append(int(analyze_url(url, url)["score"]))
    return labels, scores


def _metrics(labels: list[str], scores: list[int], threshold: int) -> dict[str, object]:
    predicted_phishing = [score >= threshold for score in scores]
    result = calculate_metrics(
        tp=sum(actual == "phishing" and predicted for actual, predicted in zip(labels, predicted_phishing)),
        tn=sum(actual == "benign" and not predicted for actual, predicted in zip(labels, predicted_phishing)),
        fp=sum(actual == "benign" and predicted for actual, predicted in zip(labels, predicted_phishing)),
        fn=sum(actual == "phishing" and not predicted for actual, predicted in zip(labels, predicted_phishing)),
    )
    result["balanced_accuracy"] = (result["recall"] + result["specificity"]) / 2
    return result


def _plateaus(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    plateaus: list[dict[str, object]] = []
    for row in rows:
        key = (row["tp"], row["tn"], row["fp"], row["fn"])
        if plateaus and plateaus[-1]["confusion_key"] == key and plateaus[-1]["end"] + 1 == row["threshold"]:
            plateaus[-1]["end"] = row["threshold"]
        else:
            plateaus.append({
                "start": row["threshold"],
                "end": row["threshold"],
                "confusion_key": key,
            })
    for plateau in plateaus:
        plateau.pop("confusion_key")
    return plateaus


def evaluate(dataset_path: Path, manifest_path: Path, evidence_dir: Path) -> dict[str, object]:
    started = time.perf_counter()
    labels, scores = _load_development_scores(dataset_path, manifest_path)
    curve = []
    for threshold in range(CALIBRATION_MIN_THRESHOLD, CALIBRATION_MAX_THRESHOLD + 1):
        curve.append({"threshold": threshold, **_metrics(labels, scores, threshold)})

    best_f1 = max(row["f1"] for row in curve)
    best_rows = [row for row in curve if row["f1"] == best_f1]
    best_plateaus = [plateau for plateau in _plateaus(best_rows)]
    selected_threshold = max(row["threshold"] for row in best_rows)
    selected = next(row for row in curve if row["threshold"] == selected_threshold)
    current = next(row for row in curve if row["threshold"] == CURRENT_SCREENING_THRESHOLD)

    benign_count = labels.count("benign")
    phishing_count = labels.count("phishing")
    operational_impact = {
        "threshold": selected_threshold,
        "benign": {
            "count": benign_count,
            "low_risk": sum(label == "benign" and score < selected_threshold for label, score in zip(labels, scores)),
            "medium_or_higher": sum(label == "benign" and score >= selected_threshold for label, score in zip(labels, scores)),
        },
        "phishing": {
            "count": phishing_count,
            "low_risk": sum(label == "phishing" and score < selected_threshold for label, score in zip(labels, scores)),
            "medium_or_higher": sum(label == "phishing" and score >= selected_threshold for label, score in zip(labels, scores)),
        },
    }
    for class_name in ("benign", "phishing"):
        item = operational_impact[class_name]
        item["low_risk_percent"] = item["low_risk"] / item["count"] * 100
        item["medium_or_higher_percent"] = item["medium_or_higher"] / item["count"] * 100

    evidence_dir.mkdir(parents=True, exist_ok=True)
    curve_path = evidence_dir / "phiusiil_h3b2_threshold_curve.csv"
    fields = ["threshold", "tp", "tn", "fp", "fn", "accuracy", "precision", "recall", "f1", "specificity", "false_positive_rate", "false_negative_rate", "balanced_accuracy"]
    with curve_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in curve:
            writer.writerow({field: row[field] for field in fields})

    risk_engine_path = Path(__file__).resolve().parents[2] / "analyzer" / "risk_engine.py"
    main_path = Path(__file__).resolve().parents[2] / "main.py"
    selection = {
        "experiment": "H3B2 screening-threshold calibration",
        "development_only": True,
        "holdout_touched": False,
        "rows_evaluated": len(labels),
        "class_counts": {"benign": benign_count, "phishing": phishing_count},
        "pre_registered_selection_rule": "Maximum development F1; ties use the highest threshold in the identical-prediction plateau.",
        "threshold_range": [CALIBRATION_MIN_THRESHOLD, CALIBRATION_MAX_THRESHOLD],
        "best_f1": best_f1,
        "best_f1_plateaus": best_plateaus,
        "selected_threshold": selected_threshold,
        "current_threshold": CURRENT_SCREENING_THRESHOLD,
        "high_risk_threshold_unchanged": HIGH_RISK_THRESHOLD,
        "selected_metrics": selected,
        "current_metrics": current,
        "h3b1_risk_engine_sha256": H3B1_RISK_ENGINE_SHA256,
        "risk_engine_sha256_at_calibration": hashlib.sha256(risk_engine_path.read_bytes()).hexdigest(),
        "h3b2_scoring_file": "Backend/main.py",
        "h3b2_main_py_sha256": hashlib.sha256(main_path.read_bytes()).hexdigest(),
        "runtime_seconds": time.perf_counter() - started,
    }
    (evidence_dir / "phiusiil_h3b2_threshold_selection.json").write_text(json.dumps(selection, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (evidence_dir / "phiusiil_h3b2_development_metrics.json").write_text(json.dumps({"development_only": True, "current_threshold_40": current, "selected_threshold": selected}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (evidence_dir / "phiusiil_h3b2_operational_impact.json").write_text(json.dumps(operational_impact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {"selection": selection, "operational_impact": operational_impact}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args()
    result = evaluate(args.dataset.resolve(), args.manifest.resolve(), args.evidence_dir.resolve())
    print(json.dumps({
        "rows": result["selection"]["rows_evaluated"],
        "selected_threshold": result["selection"]["selected_threshold"],
        "best_f1_plateaus": result["selection"]["best_f1_plateaus"],
        "holdout_touched": result["selection"]["holdout_touched"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
