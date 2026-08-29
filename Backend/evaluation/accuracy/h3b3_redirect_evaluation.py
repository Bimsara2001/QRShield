"""Verify H3B2 development metrics remain unchanged after H3B3."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path

from analyzer.risk_engine import analyze_url
from .metrics import calculate_metrics


def _metrics(labels: list[str], scores: list[int], threshold: int) -> dict[str, object]:
    positive = [score >= threshold for score in scores]
    return calculate_metrics(
        tp=sum(label == "phishing" and pred for label, pred in zip(labels, positive)),
        tn=sum(label == "benign" and not pred for label, pred in zip(labels, positive)),
        fp=sum(label == "benign" and pred for label, pred in zip(labels, positive)),
        fn=sum(label == "phishing" and not pred for label, pred in zip(labels, positive)),
    )


def evaluate(dataset: Path, manifest: Path, evidence_dir: Path) -> dict[str, object]:
    partitions = {}
    with manifest.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            partitions[int(row["row_number"])] = row["partition"]

    labels: list[str] = []
    scores: list[int] = []
    with dataset.open(newline="", encoding="utf-8-sig") as handle:
        for row_number, row in enumerate(csv.DictReader(handle), 1):
            if partitions[row_number] != "development":
                continue
            url = (row.get("URL") or "").strip()
            labels.append("benign" if row["label"] == "1" else "phishing")
            scores.append(int(analyze_url(url, url)["score"]))

    metrics = {"policy_10": _metrics(labels, scores, 10), "policy_70": _metrics(labels, scores, 70)}
    h3b2 = json.loads((evidence_dir / "phiusiil_h3b2_development_metrics.json").read_text(encoding="utf-8"))
    expected = {"policy_10": h3b2["selected_threshold"], "policy_70": None}
    unchanged = (
        metrics["policy_10"]["tp"] == expected["policy_10"]["tp"]
        and metrics["policy_10"]["tn"] == expected["policy_10"]["tn"]
        and metrics["policy_10"]["fp"] == expected["policy_10"]["fp"]
        and metrics["policy_10"]["fn"] == expected["policy_10"]["fn"]
    )

    root = Path(__file__).resolve().parents[2]
    risk_path = root / "analyzer" / "risk_engine.py"
    summary = {
        "experiment": "H3B3 redirect canonicalization fix",
        "development_only": True,
        "holdout_touched": False,
        "rows_evaluated": len(labels),
        "development_metrics": metrics,
        "h3b2_development_metrics_unchanged": unchanged,
        "redirect_normalization": {
            "normalized": ["scheme casing", "hostname casing", "one trailing hostname dot", "default http/https port", "empty path versus '/'"],
            "query_strings": "preserved and compared exactly",
            "fragments": "ignored because they are not sent to the server",
            "network_access": False,
        },
        "previous_h3b1_risk_engine_sha256": "121b64d4826f01f604b75a1ac15e1aef1a6b492e2b5e80f29c3ffdeba2dbefa6",
        "new_h3b3_risk_engine_sha256": hashlib.sha256(risk_path.read_bytes()).hexdigest(),
        "screening_threshold": 10,
        "high_risk_threshold": 70,
    }
    target = evidence_dir / "h3b3_redirect_normalization_summary.json"
    target.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args()
    summary = evaluate(args.dataset.resolve(), args.manifest.resolve(), args.evidence_dir.resolve())
    print(json.dumps({"rows": summary["rows_evaluated"], "holdout_touched": summary["holdout_touched"], "unchanged": summary["h3b2_development_metrics_unchanged"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
