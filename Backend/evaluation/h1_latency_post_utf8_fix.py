"""Run the H1 latency methodology without overwriting pre-fix evidence."""

from __future__ import annotations

import argparse
import csv
import json
import statistics
from collections import defaultdict
from pathlib import Path

from evaluation.h1_latency import SAFE_TARGETS, percentile, scan


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--count", type=int, default=50)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--output-dir", type=Path, default=Path("evaluation/evidence"))
    arguments = parser.parse_args()
    if arguments.count < 1:
        parser.error("--count must be at least one")

    arguments.output_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, object]] = []
    for number in range(1, arguments.count + 1):
        target = SAFE_TARGETS[(number - 1) % len(SAFE_TARGETS)]
        row = scan(arguments.base_url, target, arguments.timeout)
        row["scan_number"] = number
        row["target_domain"] = target.split("//", 1)[1].split("/", 1)[0]
        rows.append(row)
        print(f"{number}/{arguments.count}: {row['target_domain']} {row['status']} {row['latency_seconds']}s")

    columns = ["scan_number", "target_domain", "start_time", "end_time", "latency_seconds", "status", "verdict"]
    scans_path = arguments.output_dir / "latency_scans_post_utf8_fix.csv"
    with scans_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)

    latencies = [float(row["latency_seconds"]) for row in rows]
    successes = [row for row in rows if row["status"] == "success"]
    by_domain: dict[str, dict[str, object]] = {}
    grouped: defaultdict[str, list[dict[str, object]]] = defaultdict(list)
    for row in rows:
        grouped[str(row["target_domain"])].append(row)
    for domain, domain_rows in grouped.items():
        domain_latencies = [float(row["latency_seconds"]) for row in domain_rows]
        domain_successes = sum(row["status"] == "success" for row in domain_rows)
        by_domain[domain] = {
            "count": len(domain_rows),
            "successful_scans": domain_successes,
            "failed_scans": len(domain_rows) - domain_successes,
            "minimum": min(domain_latencies),
            "maximum": max(domain_latencies),
            "mean": statistics.mean(domain_latencies),
        }

    summary = {
        "measurement": "overall_fastapi_scan_latency_seconds_post_utf8_fix",
        "count": len(rows),
        "successful_scans": len(successes),
        "failed_scans": len(rows) - len(successes),
        "minimum": min(latencies),
        "maximum": max(latencies),
        "mean": statistics.mean(latencies),
        "median": statistics.median(latencies),
        "standard_deviation": statistics.stdev(latencies) if len(latencies) > 1 else 0.0,
        "p90_nearest_rank": percentile(latencies, 90),
        "p95_nearest_rank": percentile(latencies, 95),
        "targets": list(SAFE_TARGETS),
        "by_domain": by_domain,
    }
    (arguments.output_dir / "latency_summary_post_utf8_fix.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
