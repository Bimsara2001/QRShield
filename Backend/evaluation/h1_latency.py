"""Measure harmless end-to-end QRShield /scan latency without changing it."""

from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path


SAFE_TARGETS = (
    "https://example.com",
    "https://www.wikipedia.org",
    "https://www.python.org",
    "https://www.iana.org",
)


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def percentile(values: list[float], percent: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[math.ceil((percent / 100) * len(ordered)) - 1]


def scan(base_url: str, target: str, timeout: int) -> dict[str, object]:
    start = utc_now()
    started = time.perf_counter()
    request = urllib.request.Request(
        urllib.parse.urljoin(base_url.rstrip("/") + "/", "scan"),
        data=json.dumps({"url": target}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
        status = str(payload.get("status", "error"))
        verdict = payload.get("verdict", "") if status == "success" else ""
    except (OSError, ValueError, urllib.error.HTTPError):
        status = "error"
        verdict = ""
    ended = time.perf_counter()
    return {
        "start_time": start,
        "end_time": utc_now(),
        "latency_seconds": round(ended - started, 6),
        "status": status,
        "verdict": verdict,
    }


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
    rows = []
    for number in range(1, arguments.count + 1):
        target = SAFE_TARGETS[(number - 1) % len(SAFE_TARGETS)]
        row = scan(arguments.base_url, target, arguments.timeout)
        row["scan_number"] = number
        row["target_domain"] = urllib.parse.urlsplit(target).hostname
        rows.append(row)
        print(f"{number}/{arguments.count}: {row['target_domain']} {row['status']} {row['latency_seconds']}s")

    columns = ["scan_number", "target_domain", "start_time", "end_time", "latency_seconds", "status", "verdict"]
    with (arguments.output_dir / "latency_scans.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)

    latencies = [float(row["latency_seconds"]) for row in rows]
    successes = [row for row in rows if row["status"] == "success"]
    summary = {
        "measurement": "overall_fastapi_scan_latency_seconds",
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
    }
    (arguments.output_dir / "latency_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
