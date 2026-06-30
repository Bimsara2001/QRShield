import csv
import time

from analyzer.risk_engine import analyze_url

dataset_file = "evaluation_dataset.csv"

total = 0
correct = 0

results = []

with open(
    dataset_file,
    newline="",
    encoding="utf-8"
) as file:

    reader = csv.DictReader(file)

    for row in reader:

        url = row["url"]
        actual = row["label"]

        start = time.time()

        try:
            result = analyze_url(
                url,
                url
            )

            score = result["score"]

            predicted = (
                "suspicious"
                if score >= 40
                else "legitimate"
            )

        except Exception:
            predicted = "suspicious"

        end = time.time()

        latency = round(
            end - start,
            3
        )

        if predicted == actual:
            correct += 1

        total += 1

        results.append({
            "url": url,
            "actual": actual,
            "predicted": predicted,
            "latency": latency
        })


accuracy = correct / total * 100

avg_latency = (
    sum(r["latency"] for r in results) / total
)

tp = 0
tn = 0
fp = 0
fn = 0

for r in results:

    actual = r["actual"]
    predicted = r["predicted"]

    if actual == "suspicious" and predicted == "suspicious":
        tp += 1

    elif actual == "legitimate" and predicted == "legitimate":
        tn += 1

    elif actual == "legitimate" and predicted == "suspicious":
        fp += 1

    elif actual == "suspicious" and predicted == "legitimate":
        fn += 1


precision = (
    tp / (tp + fp)
    if (tp + fp) > 0
    else 0
)

recall = (
    tp / (tp + fn)
    if (tp + fn) > 0
    else 0
)

f1 = (
    2 * precision * recall /
    (precision + recall)
    if (precision + recall) > 0
    else 0
)


print("\n========== QRShield Evaluation ==========")

print(f"Total Samples : {total}")
print(f"Correct       : {correct}")
print(f"Accuracy      : {accuracy:.2f}%")
print(f"Avg Latency   : {avg_latency:.3f}s")

print("\n===== Confusion Matrix =====")
print(f"TP : {tp}")
print(f"TN : {tn}")
print(f"FP : {fp}")
print(f"FN : {fn}")

print("\n===== Metrics =====")
print(f"Precision : {precision:.2f}")
print(f"Recall    : {recall:.2f}")
print(f"F1 Score  : {f1:.2f}")

print("\n===== Sample Results =====\n")

for r in results:
    print(
        f"{r['actual']} | "
        f"{r['predicted']} | "
        f"{r['latency']}s | "
        f"{r['url']}"
    )