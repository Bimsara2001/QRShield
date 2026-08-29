"""Run the QRShield regression suite and save a concise H1 result."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evaluation" / "evidence"
BASE_TEMP = ROOT / ".pytest-h1-evidence"


def main() -> int:
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    if BASE_TEMP.exists():
        shutil.rmtree(BASE_TEMP)
    started = time.perf_counter()
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "--basetemp", str(BASE_TEMP)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        shell=False,
        check=False,
    )
    elapsed = time.perf_counter() - started
    output = (completed.stdout or "") + (completed.stderr or "")
    passed = failed = skipped = 0
    for token, key in (("passed", "passed"), ("failed", "failed"), ("skipped", "skipped")):
        match = re.search(rf"(\d+)\s+{token}", output)
        if match:
            value = int(match.group(1))
            if key == "passed":
                passed = value
            elif key == "failed":
                failed = value
            else:
                skipped = value
    result = {
        "captured_at": datetime.now(UTC).isoformat(),
        "return_code": completed.returncode,
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "duration_seconds": round(elapsed, 3),
    }
    (EVIDENCE / "test_suite_result.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    shutil.rmtree(BASE_TEMP, ignore_errors=True)
    print(json.dumps(result, sort_keys=True))
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
