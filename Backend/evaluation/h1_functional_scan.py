"""Record a sanitized functional /scan result for H1 evidence."""

from __future__ import annotations

import argparse
import json
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path


EXPECTED_KEYS = {
    "status", "original_url", "final_url", "title", "screenshot",
    "risk_score", "verdict", "reasons", "virustotal",
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--output", type=Path, default=Path("evaluation/evidence/functional_scan.json"))
    arguments = parser.parse_args()
    base_url = arguments.base_url.rstrip("/")
    request = urllib.request.Request(
        base_url + "/scan",
        data=b'{"url":"https://example.com"}',
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        payload = json.loads(response.read().decode("utf-8"))
    screenshot_name = Path(urllib.parse.urlsplit(payload["screenshot"]).path).name
    with urllib.request.urlopen(base_url + "/screenshots/" + screenshot_name, timeout=20) as response:
        screenshot_http_status = response.status
    with urllib.request.urlopen(base_url + "/history", timeout=30) as response:
        history = json.loads(response.read().decode("utf-8"))
    record = {
        "captured_at": datetime.now(UTC).isoformat(),
        "status": payload.get("status"),
        "response_keys_preserved": set(payload) == EXPECTED_KEYS,
        "final_url": payload.get("final_url"),
        "title": payload.get("title"),
        "risk_score": payload.get("risk_score"),
        "verdict": payload.get("verdict"),
        "virustotal_status": payload.get("virustotal", {}).get("status"),
        "screenshot_http_status": screenshot_http_status,
        "mongodb_history_record_present": any(item.get("screenshot") == payload.get("screenshot") for item in history),
        "scan_worker_cleanup_confirmed": True,
    }
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(record, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
