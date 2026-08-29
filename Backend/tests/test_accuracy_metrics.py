from evaluation.accuracy.metrics import calculate_metrics, confusion_counts, metrics_from_predictions


def test_calculate_metrics_for_reference_confusion_matrix():
    metrics = calculate_metrics(tp=8, tn=9, fp=1, fn=2)

    assert metrics["tp"] == 8
    assert metrics["tn"] == 9
    assert metrics["fp"] == 1
    assert metrics["fn"] == 2
    assert metrics["accuracy"] == 17 / 20
    assert metrics["precision"] == 8 / 9
    assert metrics["recall"] == 8 / 10
    assert metrics["f1"] == 2 * (8 / 9) * (8 / 10) / ((8 / 9) + (8 / 10))
    assert metrics["specificity"] == 9 / 10
    assert metrics["false_positive_rate"] == 1 / 10
    assert metrics["false_negative_rate"] == 2 / 10


def test_zero_denominators_are_safe():
    metrics = calculate_metrics(tp=0, tn=0, fp=0, fn=0)

    assert metrics["accuracy"] == 0.0
    assert metrics["precision"] == 0.0
    assert metrics["recall"] == 0.0
    assert metrics["f1"] == 0.0
    assert metrics["specificity"] == 0.0
    assert metrics["false_positive_rate"] == 0.0
    assert metrics["false_negative_rate"] == 0.0


def test_prediction_confusion_counts_use_benign_as_negative_class():
    actual = ["phishing", "benign", "benign", "phishing"]
    predicted = ["phishing", "benign", "phishing", "benign"]

    assert confusion_counts(actual, predicted) == (1, 1, 1, 1)
    assert metrics_from_predictions(actual, predicted)["accuracy"] == 0.5
