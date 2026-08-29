"""Evaluate only the H3B1 shortener-hostname fix on development rows."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import statistics
import time
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

from analyzer.risk_engine import SHORTENERS, _shortener_hostname_matches, analyze_url

from .metrics import calculate_metrics


OLD_RISK_ENGINE_SHA256 = "2b6e26c1dd081e38931aeb24186114ab4c00e1a873f14b5406a96d54e7d9e167"


def score_bands(scores: list[int]) -> dict[str, int]:
    return {
        "0": sum(score == 0 for score in scores),
        "1_9": sum(1 <= score <= 9 for score in scores),
        "10_19": sum(10 <= score <= 19 for score in scores),
        "20_29": sum(20 <= score <= 29 for score in scores),
        "30_39": sum(30 <= score <= 39 for score in scores),
        "40_69": sum(40 <= score <= 69 for score in scores),
        "70_plus": sum(score >= 70 for score in scores),
    }


def metrics(actual: list[str], scores: list[int], threshold: int) -> dict[str, object]:
    predictions = ["phishing" if score >= threshold else "benign" for score in scores]
    result = calculate_metrics(
        tp=sum(a == "phishing" and p == "phishing" for a, p in zip(actual, predictions)),
        tn=sum(a == "benign" and p == "benign" for a, p in zip(actual, predictions)),
        fp=sum(a == "benign" and p == "phishing" for a, p in zip(actual, predictions)),
        fn=sum(a == "phishing" and p == "benign" for a, p in zip(actual, predictions)),
    )
    result["balanced_accuracy"] = (result["recall"] + result["specificity"]) / 2
    return result


def distribution(scores: list[int]) -> dict[str, int | float | None]:
    ordered = sorted(scores)
    def percentile(percent: int) -> int | None:
        if not ordered:
            return None
        return ordered[max(0, math.ceil(percent * len(ordered) / 100) - 1)]
    return {
        "count": len(scores),
        "minimum": min(scores) if scores else None,
        "maximum": max(scores) if scores else None,
        "mean": statistics.mean(scores) if scores else None,
        "median": statistics.median(scores) if scores else None,
        "standard_deviation": statistics.stdev(scores) if len(scores) > 1 else 0.0 if scores else None,
        "p25": percentile(25),
        "p75": percentile(75),
        "p90": percentile(90),
        "p95": percentile(95),
    }


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def evaluate(dataset_path: Path, manifest_path: Path, evidence_dir: Path) -> dict[str, object]:
    manifest: dict[int, str] = {}
    with manifest_path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            manifest[int(row["row_number"])] = row["partition"]

    actual: list[str] = []
    before_scores: list[int] = []
    after_scores: list[int] = []
    before_shortener = Counter()
    after_shortener = Counter()
    benign_domains_after = Counter()
    phishing_domains_after = Counter()
    old_shortener_false_positive_records = []
    newly_fixed_records = []
    phishing_lost_records = []
    started = time.perf_counter()

    with dataset_path.open(newline="", encoding="utf-8-sig") as handle:
        for row_number, row in enumerate(csv.DictReader(handle), 1):
            if manifest[row_number] != "development":
                continue
            url = (row.get("URL") or "").strip()
            ground_truth = "benign" if row["label"] == "1" else "phishing"
            old_match = any(shortener in url.lower() for shortener in SHORTENERS)
            new_matches = [shortener for shortener in SHORTENERS if _shortener_hostname_matches(url, shortener)]
            new_match = bool(new_matches)
            result = analyze_url(url, url)
            after_score = int(result["score"])
            before_score = after_score
            if old_match and not new_match:
                before_score += 40
            elif new_match and not old_match:
                before_score -= 40

            actual.append(ground_truth)
            before_scores.append(before_score)
            after_scores.append(after_score)
            before_shortener[ground_truth] += old_match
            after_shortener[ground_truth] += new_match
            domain = urlsplit(url).hostname or "invalid-host"
            sample = {
                "sample_id": f"phiusiil-{row_number:06d}",
                "domain": domain,
                "url_sha256": hashlib.sha256(url.encode("utf-8")).hexdigest(),
                "ground_truth": ground_truth,
                "before_score": before_score,
                "after_score": after_score,
                "new_shortener_matches": new_matches,
                "reasons_after": result.get("reasons", []),
            }
            if new_match and ground_truth == "benign":
                benign_domains_after[domain] += 1
            if new_match and ground_truth == "phishing":
                phishing_domains_after[domain] += 1
            if ground_truth == "benign" and old_match and before_score >= 40:
                old_shortener_false_positive_records.append(sample)
            if ground_truth == "benign" and old_match and not new_match and before_score >= 40 and after_score < 40:
                newly_fixed_records.append(sample)
            if ground_truth == "phishing" and old_match and not new_match and before_score >= 40 and after_score < 40:
                phishing_lost_records.append(sample)

    runtime = time.perf_counter() - started
    old_metrics = {"policy_40": metrics(actual, before_scores, 40), "policy_70": metrics(actual, before_scores, 70)}
    new_metrics = {"policy_40": metrics(actual, after_scores, 40), "policy_70": metrics(actual, after_scores, 70)}
    old_h2a = json.loads((evidence_dir / "phiusiil_development_baseline.json").read_text(encoding="utf-8"))
    old_baseline_metrics = old_h2a["policies"]
    for policy in ("policy_40", "policy_70"):
        for key in ("tp", "tn", "fp", "fn"):
            if old_metrics[policy][key] != old_baseline_metrics[policy][key]:
                raise RuntimeError(f"Legacy reconstruction differs from H3A baseline for {policy}/{key}.")

    sweep_path = evidence_dir / "phiusiil_h3b1_threshold_sweep.csv"
    sweep = []
    with sweep_path.open("w", newline="", encoding="utf-8") as handle:
        fields = ["threshold", "precision", "recall", "f1", "specificity", "false_positive_rate", "false_negative_rate", "balanced_accuracy"]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for threshold in range(0, max(after_scores, default=0) + 1):
            row = {"threshold": threshold, **metrics(actual, after_scores, threshold)}
            writer.writerow({field: row[field] for field in fields})
            sweep.append(row)
    best_f1 = max(sweep, key=lambda row: (row["f1"], -row["threshold"])) if sweep else None
    best_balanced = max(sweep, key=lambda row: (row["balanced_accuracy"], -row["threshold"])) if sweep else None

    old_by_class = {label: [score for score, actual_label in zip(before_scores, actual) if actual_label == label] for label in ("benign", "phishing")}
    new_by_class = {label: [score for score, actual_label in zip(after_scores, actual) if actual_label == label] for label in ("benign", "phishing")}
    old_hash = hashlib.sha256((Path(__file__).resolve().parents[2] / "analyzer" / "risk_engine.py").read_bytes()).hexdigest()
    # The file hash is new at this point; the legacy hash is explicitly retained above.
    summary = {
        "experiment": "H3B1 shortener-hostname fix",
        "development_only": True,
        "holdout_touched": False,
        "rows_evaluated": len(actual),
        "existing_shortener_domains": SHORTENERS,
        "old_risk_engine_sha256": OLD_RISK_ENGINE_SHA256,
        "new_risk_engine_sha256": old_hash,
        "production_thresholds_unchanged": {"policy_40": 40, "policy_70": 70},
        "matching_change": "hostname equals configured shortener or ends with '.' + configured shortener; one trailing dot normalized; no DNS",
        "before_metrics": old_metrics,
        "after_metrics": new_metrics,
        "shortener_triggers": {
            "benign_before": before_shortener["benign"],
            "benign_after": after_shortener["benign"],
            "phishing_before": before_shortener["phishing"],
            "phishing_after": after_shortener["phishing"],
            "benign_false_positive_before": len(old_shortener_false_positive_records),
            "benign_false_positive_removed": len(newly_fixed_records),
            "legitimate_configured_shortener_after": after_shortener["benign"],
            "legitimate_configured_shortener_domains": dict(benign_domains_after),
            "phishing_detections_lost_policy_40": len(phishing_lost_records),
            "phishing_detections_lost_policy_70": sum(r["before_score"] >= 70 and r["after_score"] < 70 for r in phishing_lost_records),
        },
        "score_bands_before": {label: score_bands(scores) for label, scores in old_by_class.items()},
        "score_bands_after": {label: score_bands(scores) for label, scores in new_by_class.items()},
        "score_distributions_before": {label: distribution(scores) for label, scores in old_by_class.items()},
        "score_distributions_after": {label: distribution(scores) for label, scores in new_by_class.items()},
        "best_development_f1_candidate": {"threshold": best_f1["threshold"], "f1": best_f1["f1"]} if best_f1 else None,
        "best_development_balanced_accuracy_candidate": {"threshold": best_balanced["threshold"], "balanced_accuracy": best_balanced["balanced_accuracy"]} if best_balanced else None,
        "offline_runtime_seconds": runtime,
        "offline_urls_per_second": len(actual) / runtime if runtime else None,
    }
    write_json(evidence_dir / "phiusiil_h3b1_shortener_fix_summary.json", summary)
    write_json(evidence_dir / "phiusiil_h3b1_development_metrics.json", {"before": old_metrics, "after": new_metrics, "development_only": True})
    write_json(evidence_dir / "phiusiil_h3b1_score_distribution.json", {"before": summary["score_bands_before"], "after": summary["score_bands_after"]})
    write_json(evidence_dir / "phiusiil_h3b1_shortener_impact.json", {
        "before_false_positive_samples": old_shortener_false_positive_records[:20],
        "removed_false_positive_samples": newly_fixed_records[:20],
        "phishing_detection_loss_samples": phishing_lost_records[:20],
        "development_only": True,
    })
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args()
    summary = evaluate(args.dataset.resolve(), args.manifest.resolve(), args.evidence_dir.resolve())
    print(json.dumps({"rows": summary["rows_evaluated"], "holdout_touched": summary["holdout_touched"], "removed_false_positives": summary["shortener_triggers"]["benign_false_positive_removed"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
