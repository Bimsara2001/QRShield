"""Produce H3A development audits and one locked holdout baseline."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import statistics
import time
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlsplit

from analyzer.risk_engine import SHORTENERS, SUSPICIOUS_KEYWORDS, analyze_url

from .metrics import calculate_metrics


def verdict(score: int) -> str:
    if score < 40:
        return "Low Risk"
    if score < 70:
        return "Medium Risk"
    return "High Risk"


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


def contribution_category(reason: str) -> str:
    if reason == "URL does not use HTTPS":
        return "non_https"
    if reason == "Very long URL":
        return "url_length"
    if reason.startswith("Suspicious keyword detected:"):
        return "suspicious_keywords"
    if reason == "Too many dots in URL":
        return "dot_count"
    if reason == "URL shortener detected":
        return "shortener"
    if reason == "IP address used instead of domain":
        return "ip_address"
    if reason == "Hyphenated URL detected":
        return "hyphen"
    if reason == "Suspiciously long domain name":
        return "domain_length"
    if reason == "Multiple hyphens detected":
        return "multiple_hyphens"
    if reason == "URL redirected to another address":
        return "redirect"
    return "other_current_rule"


def feature_audit(risk_engine_path: Path) -> dict[str, object]:
    features: list[dict[str, object]] = [
        {"feature": "https", "condition": "not url.startswith('https://')", "score_added": 15, "reason_text": "URL does not use HTTPS"},
        {"feature": "url_length", "condition": "len(url) > 75", "score_added": 10, "reason_text": "Very long URL"},
        {"feature": "dot_count", "condition": "url.count('.') > 4", "score_added": 10, "reason_text": "Too many dots in URL"},
        {"feature": "shortener", "condition": "shortener substring in url.lower()", "score_added": 40, "reason_text": "URL shortener detected", "values": SHORTENERS},
        {"feature": "ip_address", "condition": "IPv4 regex matches anywhere in URL", "score_added": 25, "reason_text": "IP address used instead of domain"},
        {"feature": "hyphen", "condition": "'-' in url", "score_added": 10, "reason_text": "Hyphenated URL detected"},
        {"feature": "multiple_hyphens", "condition": "url.count('-') >= 2", "score_added": 15, "reason_text": "Multiple hyphens detected"},
        {"feature": "redirect", "condition": "url != final_url", "score_added": 10, "reason_text": "URL redirected to another address"},
        {"feature": "domain_length", "condition": "len(tldextract.extract(url).domain) > 20", "score_added": 10, "reason_text": "Suspiciously long domain name"},
    ]
    features.extend(
        {"feature": f"suspicious_keyword:{keyword}", "condition": f"'{keyword}' in url.lower()", "score_added": weight, "reason_text": f"Suspicious keyword detected: {keyword}"}
        for keyword, weight in SUSPICIOUS_KEYWORDS.items()
    )
    return {
        "source_file": str(risk_engine_path),
        "source_sha256": hashlib.sha256(risk_engine_path.read_bytes()).hexdigest(),
        "features": features,
        "verdict_ranges": {"Low Risk": "score < 40", "Medium Risk": "40 <= score < 70", "High Risk": "score >= 70"},
    }


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def analyze(dataset_path: Path, manifest_path: Path, evidence_dir: Path) -> None:
    manifest: dict[int, str] = {}
    with manifest_path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            manifest[int(row["row_number"])] = row["partition"]

    partition_actual: dict[str, list[str]] = {"development": [], "holdout": []}
    partition_scores: dict[str, list[int]] = {"development": [], "holdout": []}
    dev_records: list[dict[str, object]] = []
    failures = {"development": Counter(), "holdout": Counter()}
    started = time.perf_counter()
    with dataset_path.open(newline="", encoding="utf-8-sig") as handle:
        for row_number, row in enumerate(csv.DictReader(handle), 1):
            partition = manifest[row_number]
            url = (row.get("URL") or "").strip()
            label = row["label"]
            actual = "benign" if label == "1" else "phishing"
            try:
                result = analyze_url(url, url)
                score = int(result["score"])
                reasons = [str(reason) for reason in result.get("reasons", [])]
            except Exception as exc:
                failures[partition][type(exc).__name__] += 1
                continue
            partition_actual[partition].append(actual)
            partition_scores[partition].append(score)
            if partition == "development":
                dev_records.append({
                    "sample_id": f"phiusiil-{row_number:06d}",
                    "domain": urlsplit(url).hostname or "invalid-host",
                    "url_sha256": hashlib.sha256(url.encode("utf-8")).hexdigest(),
                    "ground_truth": actual,
                    "risk_score": score,
                    "verdict": verdict(score),
                    "reasons": reasons,
                    "shortener_matches": [shortener for shortener in SHORTENERS if shortener in url.lower()],
                })
    runtime = time.perf_counter() - started

    development_metrics = {
        "policy_40": metrics(partition_actual["development"], partition_scores["development"], 40),
        "policy_70": metrics(partition_actual["development"], partition_scores["development"], 70),
    }
    holdout_metrics = {
        "policy_40": metrics(partition_actual["holdout"], partition_scores["holdout"], 40),
        "policy_70": metrics(partition_actual["holdout"], partition_scores["holdout"], 70),
    }
    class_scores = {
        "benign": [r["risk_score"] for r in dev_records if r["ground_truth"] == "benign"],
        "phishing": [r["risk_score"] for r in dev_records if r["ground_truth"] == "phishing"],
    }
    development_baseline = {
        "partition": "development",
        "rows": len(partition_scores["development"]),
        "class_counts": dict(Counter(partition_actual["development"])),
        "successful_analyses": len(partition_scores["development"]),
        "failed_analyses": sum(failures["development"].values()),
        "analysis_coverage": len(partition_scores["development"]) / (len(partition_scores["development"]) + sum(failures["development"].values())) if partition_scores["development"] or failures["development"] else 0.0,
        "policies": development_metrics,
        "score_bands": {label: score_bands(scores) for label, scores in class_scores.items()},
        "offline_runtime_seconds": runtime,
    }
    holdout_baseline = {
        "partition": "holdout",
        "holdout_locked": True,
        "rows": len(partition_scores["holdout"]),
        "class_counts": dict(Counter(partition_actual["holdout"])),
        "successful_analyses": len(partition_scores["holdout"]),
        "failed_analyses": sum(failures["holdout"].values()),
        "analysis_coverage": len(partition_scores["holdout"]) / (len(partition_scores["holdout"]) + sum(failures["holdout"].values())) if partition_scores["holdout"] or failures["holdout"] else 0.0,
        "policies": holdout_metrics,
        "note": "Aggregate frozen baseline only. Holdout error details, reasons, sample identifiers, and threshold sweeps are intentionally withheld until final H3 evaluation.",
    }
    _write_json(evidence_dir / "phiusiil_development_baseline.json", development_baseline)
    _write_json(evidence_dir / "phiusiil_holdout_baseline_locked.json", holdout_baseline)

    reason_counts = Counter()
    for record in dev_records:
        if record["ground_truth"] == "phishing" and record["risk_score"] < 40:
            reason_counts.update(contribution_category(reason) for reason in set(record["reasons"]))
    _write_json(evidence_dir / "phiusiil_feature_contribution_audit.json", {
        **feature_audit(Path(__file__).resolve().parents[2] / "analyzer" / "risk_engine.py"),
        "development_phishing_false_negative_policy_40_reason_frequency": dict(reason_counts),
    })

    benign_fps = [r for r in dev_records if r["ground_truth"] == "benign" and r["risk_score"] >= 40]
    shortener_fps = [r for r in benign_fps if "URL shortener detected" in r["reasons"]]
    shortener_domains = Counter(r["domain"] for r in shortener_fps)
    shortener_matches = Counter(match for record in shortener_fps for match in record["shortener_matches"])
    error_analysis = {
        "development_only": True,
        "policy_40_false_positives": {
            "count": len(benign_fps),
            "top_reasons": Counter(reason for r in benign_fps for reason in set(r["reasons"])),
            "shortener_trigger_count": len(shortener_fps),
            "shortener_domains": dict(shortener_domains.most_common()),
            "shortener_match_strings": dict(shortener_matches),
            "shortener_logic_diagnosis": "risk_engine.py checks whether each shortener string is a substring of the full lower-cased URL; it does not parse and compare the hostname.",
            "shortener_samples": shortener_fps[:20],
        },
        "phishing_false_negative_policy_40": {
            "count": sum(r["ground_truth"] == "phishing" and r["risk_score"] < 40 for r in dev_records),
            "reason_frequency": dict(reason_counts),
            "score_bands": score_bands([r["risk_score"] for r in dev_records if r["ground_truth"] == "phishing" and r["risk_score"] < 40]),
            "samples": [r for r in dev_records if r["ground_truth"] == "phishing" and r["risk_score"] < 40][:20],
        },
        "candidate_improvements_not_implemented": [
            {"category": "A. bug fix", "problem": "Shortener substring matching creates development false positives.", "smallest_change": "Compare parsed hostname against exact shortener hosts or explicit subdomains.", "tradeoff": "May miss unusual shortener URL forms; reduces accidental substring matches.", "overfitting_risk": "Validate on locked holdout before adoption."},
            {"category": "B. heuristic precision improvement", "problem": "Broad hyphen and multiple-hyphen penalties affect benign and phishing URLs.", "smallest_change": "Audit host/path context before applying the existing penalties.", "tradeoff": "Could reduce false positives but miss hyphenated phishing domains.", "overfitting_risk": "High if based only on development domains."},
            {"category": "C. score-weight calibration", "problem": "Many development phishing URLs remain below score 40.", "smallest_change": "Reconsider existing contribution magnitudes using development-only evidence.", "tradeoff": "Higher recall may increase false positives.", "overfitting_risk": "High without holdout confirmation."},
            {"category": "D. threshold calibration", "problem": "Development threshold curve may identify candidate operating points.", "smallest_change": "Evaluate candidates only; do not change production threshold in H3A.", "tradeoff": "Threshold changes trade recall against false-positive rate.", "overfitting_risk": "Must be selected without inspecting holdout outcomes."},
            {"category": "E. new lexical feature", "problem": "Current URL-only rules do not capture all phishing structure.", "smallest_change": "Design one independently specified lexical feature for H3B.", "tradeoff": "Adds complexity and new false-positive modes.", "overfitting_risk": "Requires preregistered rationale and holdout evaluation."},
        ],
    }
    error_analysis["policy_40_false_positives"]["top_reasons"] = [
        {"reason": reason, "count": count} for reason, count in error_analysis["policy_40_false_positives"]["top_reasons"].most_common()
    ]
    _write_json(evidence_dir / "phiusiil_development_error_analysis.json", error_analysis)

    sweep_path = evidence_dir / "phiusiil_development_threshold_sweep.csv"
    max_score = max(partition_scores["development"], default=0)
    with sweep_path.open("w", newline="", encoding="utf-8") as handle:
        fieldnames = ["threshold", "precision", "recall", "f1", "specificity", "false_positive_rate", "false_negative_rate", "balanced_accuracy"]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        sweep = []
        for threshold in range(0, max_score + 1):
            row = {"threshold": threshold, **metrics(partition_actual["development"], partition_scores["development"], threshold)}
            output = {field: row[field] for field in fieldnames}
            writer.writerow(output)
            sweep.append(row)
    best_f1 = max(sweep, key=lambda row: (row["f1"], -row["threshold"])) if sweep else None
    best_balanced = max(sweep, key=lambda row: (row["balanced_accuracy"], -row["threshold"])) if sweep else None
    _write_json(evidence_dir / "phiusiil_development_threshold_candidates.json", {
        "development_only": True,
        "best_f1_candidate": {"threshold": best_f1["threshold"], "f1": best_f1["f1"]} if best_f1 else None,
        "best_balanced_accuracy_candidate": {"threshold": best_balanced["threshold"], "balanced_accuracy": best_balanced["balanced_accuracy"]} if best_balanced else None,
        "production_thresholds_unchanged": {"policy_40": 40, "policy_70": 70},
    })


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args()
    analyze(args.dataset.resolve(), args.manifest.resolve(), args.evidence_dir.resolve())
    print("H3 development analysis completed; holdout output is aggregate-only and locked.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
