"""Offline external URL generalizability validation for the frozen risk engine.

Inputs are already-downloaded URL-list files.  This program never retrieves a
listed URL and imports only ``analyzer.risk_engine``.  It does not import the
application, browser/sandbox, database, or threat-intelligence modules.
"""

from __future__ import annotations

import csv
import hashlib
import json
import statistics
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


BACKEND = Path(__file__).resolve().parents[1]
DATA = BACKEND / "evaluation" / "data" / "external_generalization"
EVIDENCE = BACKEND / "evaluation" / "evidence"
PHISHTANK = DATA / "phishtank_online_valid_raw.csv"
TRANCO = DATA / "tranco_38LNL_raw.csv"
PHIUSIIL = BACKEND / "evaluation" / "data" / "phiusiil" / "PhiUSIIL_Phishing_URL_Dataset.csv"
SCREENING_THRESHOLD = 10
HIGH_RISK_THRESHOLD = 70
PER_CLASS_TARGET = 10_000
EXPECTED_HASHES = {
    "analyzer/risk_engine.py": "e837e453313a5507ac75f598884c929f929a08ca1a560d50a9cbc9919c1c00e1",
    "detectors/phishing_detector.py": "1bffa7d2099ff9411bca4035334033bcee1308fec31a367d71c962f5c27a628a",
}
H3C = {
    "accuracy": 0.863215,
    "precision": 0.848886,
    "recall": 0.827863,
    "specificity": 0.889680,
    "false_positive_rate": 0.110320,
    "false_negative_rate": 0.172137,
    "f1": 0.838243,
}

import sys
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))
from analyzer.risk_engine import analyze_url  # noqa: E402
from evaluation.accuracy.metrics import metrics_from_predictions  # noqa: E402


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def valid_url(value: str) -> bool:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    return parsed.scheme.lower() in {"http", "https"} and bool(parsed.hostname) and not any(char.isspace() for char in value)


def comparison_key(value: str) -> str | None:
    """Offline normalization solely for conservative overlap/collision checks."""
    try:
        parsed = urlsplit(value.strip())
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https"} or not host:
        return None
    scheme = parsed.scheme.lower()
    host = host.rstrip(".").lower()
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        port = None
    netloc = host if port is None else f"{host}:{port}"
    return urlunsplit((scheme, netloc, parsed.path or "/", parsed.query, ""))


def redacted_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
        return f"{parsed.scheme}://{parsed.hostname or '<invalid>'}/<redacted>"
    except ValueError:
        return "<invalid>"


def url_records(path: Path, kind: str) -> tuple[list[dict[str, str]], dict[str, int]]:
    records: list[dict[str, str]] = []
    invalid = 0
    row_number = 0
    if kind == "benign":
        # Tranco's documented Alexa/Umbrella-compatible CSV has no header:
        # ``rank,domain``.
        with path.open(newline="", encoding="utf-8-sig", errors="replace") as handle:
            for row_number, row in enumerate(csv.reader(handle), 1):
                domain = row[1].strip() if len(row) >= 2 else ""
                value = f"https://{domain}/"
                source_id = row[0].strip() if row else str(row_number)
                if not valid_url(value):
                    invalid += 1
                    continue
                records.append({"source_row_id": source_id, "url": value, "expected_label": kind})
        return records, {"raw_rows": row_number, "invalid_or_malformed_removed": invalid}
    with path.open(newline="", encoding="utf-8-sig", errors="replace") as handle:
        reader = csv.DictReader(handle)
        for row_number, row in enumerate(reader, 1):
            value = (row.get("url") or "").strip()
            source_id = (row.get("phish_id") or str(row_number)).strip()
            if not valid_url(value):
                invalid += 1
                continue
            records.append({"source_row_id": source_id, "url": value, "expected_label": kind})
    return records, {"raw_rows": row_number, "invalid_or_malformed_removed": invalid}


def exact_dedupe(records: list[dict[str, str]]) -> tuple[list[dict[str, str]], int]:
    seen: set[str] = set()
    output: list[dict[str, str]] = []
    removed = 0
    for row in records:
        if row["url"] in seen:
            removed += 1
        else:
            seen.add(row["url"])
            output.append(row)
    return output, removed


def load_phiusiil_keys() -> tuple[set[str], set[str], int]:
    exact: set[str] = set()
    normalized: set[str] = set()
    rows = 0
    with PHIUSIIL.open(newline="", encoding="utf-8-sig") as handle:
        for row in csv.DictReader(handle):
            rows += 1
            value = (row.get("URL") or "").strip()
            exact.add(value)
            key = comparison_key(value)
            if key:
                normalized.add(key)
    return exact, normalized, rows


def without_overlap(records: list[dict[str, str]], exact: set[str], normalized: set[str]) -> tuple[list[dict[str, str]], int, int]:
    output: list[dict[str, str]] = []
    exact_removed = normalized_only_removed = 0
    for row in records:
        value = row["url"]
        key = comparison_key(value)
        if value in exact:
            exact_removed += 1
        elif key and key in normalized:
            normalized_only_removed += 1
        else:
            output.append(row)
    return output, exact_removed, normalized_only_removed


def score_distribution(scores: list[int]) -> dict[str, object]:
    bands = {"0": 0, "1_9": 0, "10_19": 0, "20_29": 0, "30_39": 0, "40_69": 0, "70_plus": 0}
    for score in scores:
        if score == 0:
            bands["0"] += 1
        elif score < 10:
            bands["1_9"] += 1
        elif score < 20:
            bands["10_19"] += 1
        elif score < 30:
            bands["20_29"] += 1
        elif score < 40:
            bands["30_39"] += 1
        elif score < 70:
            bands["40_69"] += 1
        else:
            bands["70_plus"] += 1
    return {"count": len(scores), "mean": statistics.mean(scores), "median": statistics.median(scores), "minimum": min(scores), "maximum": max(scores), "bands": bands}


def limitation(expected: str, signals: str) -> str:
    if expected == "phishing":
        return "The frozen URL-lexical model has no content, reputation, redirect, or hosting signal here and did not reach its fixed screening threshold."
    if "Suspicious keyword" in signals:
        return "A frozen lexical keyword is not phishing-specific in this high-traffic-domain proxy class."
    return "A frozen structural URL heuristic is not phishing-specific in this high-traffic-domain proxy class."


def main() -> None:
    observed = {name: sha256(BACKEND / name) for name in EXPECTED_HASHES}
    mismatches = {name: {"expected": EXPECTED_HASHES[name], "actual": observed[name]} for name in EXPECTED_HASHES if observed[name] != EXPECTED_HASHES[name]}
    if mismatches:
        raise SystemExit("Frozen detector hash mismatch; evaluation aborted: " + json.dumps(mismatches))
    for required in (PHISHTANK, TRANCO, PHIUSIIL):
        if not required.is_file():
            raise SystemExit(f"Required local input is unavailable: {required}")

    acquired_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    phishing_raw, phishing_counts = url_records(PHISHTANK, "phishing")
    benign_raw, benign_counts = url_records(TRANCO, "benign")
    phishing, phishing_duplicates = exact_dedupe(phishing_raw)
    benign, benign_duplicates = exact_dedupe(benign_raw)

    phi_exact, phi_normalized, phi_rows = load_phiusiil_keys()
    phishing, p_exact_overlap, p_normalized_overlap = without_overlap(phishing, phi_exact, phi_normalized)
    benign, b_exact_overlap, b_normalized_overlap = without_overlap(benign, phi_exact, phi_normalized)

    # Remove cross-class collisions after all source/PhiUSIIL filtering. Both
    # classes are excluded for each collision, preserving a non-conflicting set.
    benign_exact = {row["url"] for row in benign}
    benign_normalized = {comparison_key(row["url"]) for row in benign}
    collision_keys = {comparison_key(row["url"]) for row in phishing if row["url"] in benign_exact or comparison_key(row["url"]) in benign_normalized}
    p_before, b_before = len(phishing), len(benign)
    phishing = [row for row in phishing if comparison_key(row["url"]) not in collision_keys]
    benign = [row for row in benign if comparison_key(row["url"]) not in collision_keys]
    collisions_removed = {"phishing": p_before - len(phishing), "benign": b_before - len(benign), "normalized_collision_keys": len(collision_keys)}

    if len(phishing) < PER_CLASS_TARGET or len(benign) < PER_CLASS_TARGET:
        raise SystemExit("Independent sources do not provide the fixed target after hygiene.")
    selected = phishing[:PER_CLASS_TARGET] + benign[:PER_CLASS_TARGET]
    for index, row in enumerate(selected, 1):
        row["case_id"] = f"external-{index:05d}"
        row["url_sha256"] = hashlib.sha256(row["url"].encode("utf-8")).hexdigest()

    manifest_fields = ["case_id", "source_row_id", "expected_label", "url", "url_sha256"]
    with (DATA / "external_generalization_clean_manifest.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=manifest_fields)
        writer.writeheader()
        writer.writerows(selected)

    results: list[dict[str, object]] = []
    for row in selected:
        analysis = analyze_url(row["url"], row["url"])
        score = int(analysis["score"])
        predicted = "phishing" if score >= SCREENING_THRESHOLD else "benign"
        results.append({**row, "risk_score": score, "predicted_label": predicted, "contributing_url_signals": " | ".join(analysis["reasons"]), "correct": str(predicted == row["expected_label"]).lower()})
    labels = [str(row["expected_label"]) for row in results]
    predictions = [str(row["predicted_label"]) for row in results]
    metrics = metrics_from_predictions(labels, predictions)
    errors = []
    for row in results:
        if row["correct"] == "false":
            signals = str(row["contributing_url_signals"]) or "None"
            errors.append({"case_id": row["case_id"], "url_sha256": row["url_sha256"], "url_redacted": redacted_url(str(row["url"])), "risk_score": row["risk_score"], "expected_label": row["expected_label"], "predicted_label": row["predicted_label"], "contributing_frozen_signals": signals, "likely_detector_limitation": limitation(str(row["expected_label"]), signals)})

    result_fields = ["case_id", "source_row_id", "expected_label", "url", "url_sha256", "risk_score", "predicted_label", "contributing_url_signals", "correct"]
    with (EVIDENCE / "external_generalization_results.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=result_fields)
        writer.writeheader()
        writer.writerows(results)
    with (EVIDENCE / "external_generalization_confusion_matrix.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["predicted_label", "actual_benign", "actual_phishing"])
        writer.writeheader()
        writer.writerows([
            {"predicted_label": "benign", "actual_benign": metrics["tn"], "actual_phishing": metrics["fn"]},
            {"predicted_label": "phishing", "actual_benign": metrics["fp"], "actual_phishing": metrics["tp"]},
        ])
    error_summary = {"evaluation_label": "External URL Generalizability Validation", "false_positive_count": metrics["fp"], "false_negative_count": metrics["fn"], "recurring_patterns": {"false_positives": "URL lexical/structural signals on ranked popular domains.", "false_negatives": "Verified phishing URLs without enough frozen lexical indicators to meet score >= 10."}, "errors": errors}
    (EVIDENCE / "external_generalization_error_analysis.json").write_text(json.dumps(error_summary, indent=2) + "\n", encoding="utf-8")

    gaps = {name: {"h3c": value, "external": metrics[name], "absolute_difference_percentage_points": (float(metrics[name]) - value) * 100, "direction_vs_h3c": "improved" if ((float(metrics[name]) > value) if name not in {"false_positive_rate", "false_negative_rate"} else (float(metrics[name]) < value)) else "degraded" if float(metrics[name]) != value else "unchanged"} for name, value in H3C.items()}
    gap_note = "A material descriptive generalization gap is present (at least one core metric differs from H3C by more than 5 percentage points)." if any(abs(item["absolute_difference_percentage_points"]) > 5 for item in gaps.values()) else "No core metric differs from H3C by more than 5 percentage points; this is descriptive only, not a statistical significance result."
    gap = {"evaluation_label": "External URL Generalizability Validation", "h3c_reference": H3C, "external_metrics": {key: metrics[key] for key in H3C}, "differences": gaps, "interpretation": gap_note, "statistical_significance_test_performed": False}
    (EVIDENCE / "external_generalization_gap.json").write_text(json.dumps(gap, indent=2) + "\n", encoding="utf-8")

    provenance = {"evaluation_label": "External URL Generalizability Validation", "acquired_at_utc": acquired_at, "sources": {"phishing": {"name": "PhishTank online-valid CSV", "source_url": "https://data.phishtank.com/data/online-valid.csv", "official_documentation": "https://www.phishtank.org/developer_info.php", "label_mapping": "verified online-valid feed row -> phishing", "raw_file": PHISHTANK.name, "sha256": sha256(PHISHTANK), **phishing_counts, "exact_duplicates_removed": phishing_duplicates, "phiusiil_exact_overlap_removed": p_exact_overlap, "phiusiil_normalized_overlap_removed": p_normalized_overlap}, "benign": {"name": "Tranco list 38LNL", "source_url": "https://tranco-list.eu/download/38LNL/1000000", "list_information_url": "https://tranco-list.eu/list/38LNL", "label_mapping": "top-ranked pay-level domain -> benign proxy; not a guarantee that every domain is benign", "raw_file": TRANCO.name, "sha256": sha256(TRANCO), **benign_counts, "exact_duplicates_removed": benign_duplicates, "phiusiil_exact_overlap_removed": b_exact_overlap, "phiusiil_normalized_overlap_removed": b_normalized_overlap}}, "phiusiil_overlap_reference": {"dataset": str(PHIUSIIL.relative_to(BACKEND)), "rows_checked": phi_rows, "method": "exact URL-string comparison plus conservative URL normalization; every matched external item was excluded"}, "cross_class_collision_removal": collisions_removed, "sampling": {"target_per_class": PER_CLASS_TARGET, "method": "first valid, deduplicated, non-overlapping records in source-file order; no score-based selection or tuning"}, "safety": "Only the two source feed files were downloaded. No listed URL was opened, fetched, navigated, submitted to VirusTotal, or sent to any service."}
    (EVIDENCE / "external_generalization_provenance.json").write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
    overlap = {"phiusiil_rows_checked": phi_rows, "external_removed_for_phiusiil_exact_overlap": p_exact_overlap + b_exact_overlap, "external_removed_for_phiusiil_normalized_only_overlap": p_normalized_overlap + b_normalized_overlap, "cross_class_collision_removal": collisions_removed, "policy": "Exclude exact and normalized PhiUSIIL matches, then exclude normalized cross-class collisions from both external classes."}
    (DATA / "external_generalization_overlap_report.json").write_text(json.dumps(overlap, indent=2) + "\n", encoding="utf-8")
    summary = {"evaluation_label": "External URL Generalizability Validation", "scope": "Offline URL text only; frozen analyze_url(url, url), no redirect data or network access.", "frozen_hashes_before_and_during_evaluation": observed, "decision_policy": "phishing if risk score >= 10, the frozen H3C screening policy; no threshold was derived or changed.", "final_counts": {"total": len(results), "phishing": labels.count("phishing"), "legitimate": labels.count("benign")}, "metrics": metrics, "score_distributions": {"all": score_distribution([int(row["risk_score"]) for row in results]), "phishing": score_distribution([int(row["risk_score"]) for row in results if row["expected_label"] == "phishing"]), "legitimate": score_distribution([int(row["risk_score"]) for row in results if row["expected_label"] == "benign"])}, "limitations": ["PhishTank is a time-varying verified-online phishing feed; label lifetime and feed coverage constrain generalization.", "Tranco is a popularity ranking used as a benign proxy, not a per-URL benign verification service.", "The balanced 10,000-per-class sample is not a prevalence estimate.", "No content, redirects, HTML, browser/sandbox, DNS, reputation, VirusTotal, MongoDB, or live URL retrieval is evaluated.", "H3C and this external validation remain separate; no statistical significance test was performed."]}
    (EVIDENCE / "external_generalization_summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"final_counts": summary["final_counts"], "metrics": metrics, "overlap": overlap, "hashes": observed}, indent=2))


if __name__ == "__main__":
    main()
