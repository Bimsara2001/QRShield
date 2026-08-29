"""Create the locked, grouped, deterministic H3 development/holdout split."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
from collections import Counter, defaultdict
from pathlib import Path


SEED = 2026
HOLDOUT_FRACTION = 0.30


def split_dataset(dataset_path: Path, manifest_path: Path, summary_path: Path) -> dict[str, object]:
    groups: dict[str, dict[str, object]] = {}
    row_count = 0
    label_counts: Counter[str] = Counter()
    with dataset_path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or "URL" not in reader.fieldnames or "label" not in reader.fieldnames:
            raise ValueError("Dataset must contain URL and label columns.")
        for row_number, row in enumerate(reader, 1):
            url = (row.get("URL") or "").strip()
            label = (row.get("label") or "").strip()
            if label not in {"0", "1"}:
                raise ValueError(f"Unexpected label at row {row_number}: {label!r}")
            row_count += 1
            label_counts[label] += 1
            group = groups.setdefault(url, {"label": label, "rows": []})
            if group["label"] != label:
                raise ValueError("A duplicate URL has conflicting labels.")
            group["rows"].append(row_number)

    by_label: defaultdict[str, list[tuple[str, dict[str, object]]]] = defaultdict(list)
    for url, group in groups.items():
        by_label[str(group["label"])].append((url, group))

    assignments: dict[int, str] = {}
    target_holdout_by_label: dict[str, int] = {}
    for label in ("0", "1"):
        target = round(label_counts[label] * HOLDOUT_FRACTION)
        target_holdout_by_label[label] = target
        candidates = sorted(by_label[label], key=lambda item: item[0])
        random.Random(SEED + int(label)).shuffle(candidates)
        selected = 0
        for _url, group in candidates:
            group_size = len(group["rows"])
            if selected + group_size <= target:
                partition = "holdout"
                selected += group_size
            else:
                partition = "development"
            for row_number in group["rows"]:
                assignments[int(row_number)] = partition
        if selected != target:
            raise RuntimeError(f"Could not reach deterministic holdout target for label {label}.")

    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with manifest_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["row_number", "partition", "original_label", "url_sha256"])
        writer.writeheader()
        with dataset_path.open(newline="", encoding="utf-8-sig") as dataset_handle:
            for row_number, row in enumerate(csv.DictReader(dataset_handle), 1):
                url = (row.get("URL") or "").strip()
                writer.writerow({
                    "row_number": row_number,
                    "partition": assignments[row_number],
                    "original_label": row["label"],
                    "url_sha256": hashlib.sha256(url.encode("utf-8")).hexdigest(),
                })

    partition_counts: dict[str, dict[str, int]] = {
        "development": {"rows": 0, "label_0_phishing": 0, "label_1_legitimate": 0},
        "holdout": {"rows": 0, "label_0_phishing": 0, "label_1_legitimate": 0},
    }
    for group in groups.values():
        label = str(group["label"])
        for row_number in group["rows"]:
            partition = assignments[int(row_number)]
            partition_counts[partition]["rows"] += 1
            partition_counts[partition]["label_0_phishing" if label == "0" else "label_1_legitimate"] += 1

    summary = {
        "seed": SEED,
        "development_fraction_target": 0.70,
        "holdout_fraction_target": HOLDOUT_FRACTION,
        "raw_row_count": row_count,
        "unique_url_groups": len(groups),
        "duplicate_url_occurrences_beyond_first": row_count - len(groups),
        "duplicate_groups": sum(len(group["rows"]) > 1 for group in groups.values()),
        "conflicting_duplicate_label_groups": 0,
        "cross_partition_duplicate_count": 0,
        "target_holdout_rows_by_label": target_holdout_by_label,
        "partitions": partition_counts,
        "manifest": manifest_path.name,
        "holdout_locked": True,
        "holdout_policy": "Only aggregate frozen baseline metrics are written; no holdout samples, reasons, errors, or threshold sweeps are emitted.",
    }
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(split_dataset(args.dataset.resolve(), args.manifest.resolve(), args.summary.resolve()), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
