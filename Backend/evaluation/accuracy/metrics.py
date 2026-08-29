"""Deterministic binary classification metrics for H2 baseline reports."""

from __future__ import annotations

from typing import Mapping


def _safe_divide(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def calculate_metrics(tp: int, tn: int, fp: int, fn: int) -> dict[str, float | int]:
    """Return confusion counts and standard metrics with safe zero handling."""
    total = tp + tn + fp + fn
    precision = _safe_divide(tp, tp + fp)
    recall = _safe_divide(tp, tp + fn)
    return {
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "total": total,
        "accuracy": _safe_divide(tp + tn, total),
        "precision": precision,
        "recall": recall,
        "f1": _safe_divide(2 * precision * recall, precision + recall),
        "specificity": _safe_divide(tn, tn + fp),
        "false_positive_rate": _safe_divide(fp, fp + tn),
        "false_negative_rate": _safe_divide(fn, fn + tp),
        "confusion_matrix": {
            "predicted_benign": {
                "ground_truth_benign": tn,
                "ground_truth_phishing": fn,
            },
            "predicted_phishing": {
                "ground_truth_benign": fp,
                "ground_truth_phishing": tp,
            },
        },
    }


def confusion_counts(
    ground_truth: list[str], predictions: list[str]
) -> tuple[int, int, int, int]:
    """Calculate ``(tp, tn, fp, fn)`` for benign/phishing labels."""
    if len(ground_truth) != len(predictions):
        raise ValueError("Ground-truth and prediction lengths differ.")
    tp = tn = fp = fn = 0
    for actual, predicted in zip(ground_truth, predictions):
        if actual == "phishing" and predicted == "phishing":
            tp += 1
        elif actual == "benign" and predicted == "benign":
            tn += 1
        elif actual == "benign" and predicted == "phishing":
            fp += 1
        elif actual == "phishing" and predicted == "benign":
            fn += 1
        else:
            raise ValueError(f"Unsupported binary label: {actual!r} or {predicted!r}")
    return tp, tn, fp, fn


def metrics_from_predictions(
    ground_truth: list[str], predictions: list[str]
) -> dict[str, float | int]:
    return calculate_metrics(*confusion_counts(ground_truth, predictions))
