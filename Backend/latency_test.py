import time
import requests

API_URL = "http://localhost:8000/scan"

test_urls = [
    "https://google.com",
    "https://github.com",
    "https://microsoft.com",
    "https://wikipedia.org",
    "https://stackoverflow.com"
]

results = []

for url in test_urls:

    print(f"Testing: {url}")

    start = time.time()

    response = requests.post(
        API_URL,
        json={
            "url": url
        },
        timeout=90
    )

    end = time.time()

    latency = round(end - start, 2)

    results.append(latency)

    print(
        f"Status: {response.status_code} | Latency: {latency}s"
    )

print("\n===== Latency Results =====")
print(f"Total Tests: {len(results)}")
print(f"Average Latency: {round(sum(results) / len(results), 2)}s")
print(f"Fastest: {min(results)}s")
print(f"Slowest: {max(results)}s")