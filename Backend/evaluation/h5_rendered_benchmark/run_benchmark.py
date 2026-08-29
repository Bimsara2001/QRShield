"""Run the fixed H5 corpus through the real QRShield Playwright worker image.

This is an opt-in evaluation controller, not a production scan path.  The
production runner deliberately rejects local/private destinations; this script
instead creates a short-lived internal-only Docker network containing only a
TLS fixture server, a fixture-only proxy, and one short-lived worker at a time.
It never imports FastAPI, MongoDB, or VirusTotal.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

BACKEND_ROOT = Path(__file__).resolve().parents[2]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from analyzer.risk_engine import analyze_url
from detectors.phishing_detector import detect_phishing


ROOT = Path(__file__).resolve().parent
FIXTURES = ROOT / "fixtures"
MANIFEST = ROOT / "manifest.csv"
PRE_INTEGRITY = ROOT / "pre_execution_integrity.json"
TLS = ROOT / ".runtime_tls"
EVIDENCE = ROOT.parent / "evidence" / "h5_rendered_benchmark"
WORKER_IMAGE = "qrshield-sandbox-worker:latest"
EVALUATION_WORKER_IMAGE = "qrshield-h5-rendered-evaluation-worker:local"
PROXY_IMAGE = "qrshield-egress-proxy:latest"
NETWORK = "qrshield-h5-rendered-evaluation"
FIXTURE_CONTAINER = "qrshield-h5-fixtures"
PROXY_CONTAINER = "qrshield-h5-evaluation-proxy"
EXPECTED_HASHES = {
    "analyzer/risk_engine.py": "e837e453313a5507ac75f598884c929f929a08ca1a560d50a9cbc9919c1c00e1",
    "detectors/phishing_detector.py": "1bffa7d2099ff9411bca4035334033bcee1308fec31a367d71c962f5c27a628a",
}
SCREENING_THRESHOLD = 10
HIGH_RISK_THRESHOLD = 70


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run(command: list[str], *, input_text: str | None = None, timeout: int = 90) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, input=input_text, text=True, encoding="utf-8", capture_output=True, timeout=timeout, check=False)


def _require_success(command: list[str], *, input_text: str | None = None, timeout: int = 90) -> subprocess.CompletedProcess[str]:
    result = _run(command, input_text=input_text, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(f"Docker command failed: {' '.join(command[:4])}; {result.stderr.strip() or 'no diagnostic'}")
    return result


def _remove_if_present(name: str, *, network: bool = False) -> None:
    command = ["docker", "network" if network else "container", "rm", "-f", name]
    _run(command, timeout=20)


def _verify_inputs() -> tuple[list[dict[str, str]], dict[str, Any]]:
    if not MANIFEST.exists() or not PRE_INTEGRITY.exists():
        raise RuntimeError("Run build_benchmark.py before executing the benchmark.")
    if (EVIDENCE / "summary.json").exists():
        raise RuntimeError("A benchmark summary already exists; refusing to overwrite the first frozen result.")

    observed_hashes = {path: _sha256(Path(path)) for path in EXPECTED_HASHES}
    if observed_hashes != EXPECTED_HASHES:
        raise RuntimeError("Frozen detector integrity mismatch; benchmark aborted before execution.")

    with MANIFEST.open(newline="", encoding="utf-8") as handle:
        cases = list(csv.DictReader(handle))
    if len(cases) != 50:
        raise RuntimeError("Manifest must contain exactly 50 benchmark cases.")
    labels = {label: sum(case["expected_label"] == label for case in cases) for label in ("benign", "phishing")}
    if labels != {"benign": 25, "phishing": 25}:
        raise RuntimeError("Manifest must contain 25 benign and 25 phishing cases.")
    for case in cases:
        fixture = ROOT / case["fixture"]
        if case.get("source") != "synthetic_independent_rendered_benchmark" or case.get("used_for_tuning") != "false":
            raise RuntimeError("Manifest provenance is invalid.")
        if not fixture.is_file() or _sha256(fixture) != case.get("fixture_sha256"):
            raise RuntimeError(f"Fixture integrity mismatch for {case['case_id']}.")
    integrity = json.loads(PRE_INTEGRITY.read_text(encoding="utf-8"))
    if integrity.get("direct_historical_content_duplicate_count") != 0 or integrity.get("historical_case_id_collision_count") != 0:
        raise RuntimeError("Independence check failed before execution.")
    if integrity.get("manifest_sha256") != _sha256(MANIFEST):
        raise RuntimeError("Manifest changed after pre-execution freeze.")
    return cases, {"before_hashes": observed_hashes, "pre_execution": integrity}


def _create_tls_material() -> Path:
    TLS.mkdir(parents=True, exist_ok=False)
    script = """
set -eu
cp /etc/ssl/certs/ca-certificates.crt /out/base-ca-bundle.crt
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=QRShield-H5-Evaluation-CA -keyout /out/ca.key -out /out/ca.crt
openssl req -newkey rsa:2048 -nodes -subj /CN=h5fixtures -addext subjectAltName=DNS:h5fixtures -keyout /out/server.key -out /out/server.csr
openssl x509 -req -days 1 -in /out/server.csr -CA /out/ca.crt -CAkey /out/ca.key -CAcreateserial -out /out/server.crt -copy_extensions copy
cat /out/base-ca-bundle.crt /out/ca.crt > /out/worker-ca-bundle.crt
chmod 644 /out/server.key
"""
    _require_success([
        "docker", "run", "--rm", "--network", "none", "--user", "0",
        "--mount", f"type=bind,src={TLS.resolve()},dst=/out", "--entrypoint", "bash", WORKER_IMAGE, "-lc", script,
    ])
    _require_success([
        "docker", "build", "--pull=false", "--tag", EVALUATION_WORKER_IMAGE,
        "--file", str((ROOT / "evaluation_worker.Dockerfile").resolve()), str(TLS.resolve()),
    ], timeout=180)
    return TLS / "worker-ca-bundle.crt"


def _start_topology(ca_bundle: Path) -> None:
    _require_success(["docker", "network", "create", "--internal", "--subnet", "172.30.240.0/24", NETWORK])
    _require_success([
        "docker", "run", "-d", "--rm", "--name", FIXTURE_CONTAINER, "--network", NETWORK,
        "--network-alias", "h5fixtures", "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,size=32m",
        "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
        "--mount", f"type=bind,src={FIXTURES.resolve()},dst=/fixtures,readonly",
        "--mount", f"type=bind,src={TLS.resolve()},dst=/tls,readonly",
        "--entrypoint", "python", WORKER_IMAGE, "-u", "/fixtures/https_server.py", "--directory", "/fixtures",
        "--certfile", "/tls/server.crt", "--keyfile", "/tls/server.key", "--port", "8443",
    ])
    _require_success([
        "docker", "run", "-d", "--rm", "--name", PROXY_CONTAINER, "--network", NETWORK,
        "--network-alias", "h5evalproxy", "--read-only", "--tmpfs", "/run:rw,nosuid,nodev,size=16m",
        "--tmpfs", "/var/spool/squid:rw,nosuid,nodev,size=32m", "--tmpfs", "/var/log/squid:rw,nosuid,nodev,size=16m",
        # Squid must retain its normal setgid capability to transition to its
        # configured service account. This proxy is nevertheless internal-only
        # and ACL-limited to h5fixtures:8443, with no egress network attached.
        "--security-opt=no-new-privileges:true",
        "--mount", f"type=bind,src={(ROOT / 'h5_eval_squid.conf').resolve()},dst=/etc/squid/squid.conf,readonly",
        PROXY_IMAGE,
    ])
    time.sleep(1)
    for name in (FIXTURE_CONTAINER, PROXY_CONTAINER):
        status = _require_success(["docker", "inspect", "--format", "{{.State.Running}}", name]).stdout.strip()
        if status.lower() != "true":
            raise RuntimeError(f"Evaluation topology container is not running: {name}")


def _run_worker(url: str, ca_bundle: Path, case_id: str) -> tuple[dict[str, Any] | None, str | None, float]:
    command = [
        "docker", "run", "--rm", "--name", f"qrshield-h5-{case_id.lower()}", "--init", "-i", "--network", NETWORK,
        "-e", "QRSHIELD_EGRESS_PROXY=http://h5evalproxy:3128", "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m",
        "--cpus=1", "--memory=1g", "--pids-limit=256", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
        "--shm-size=256m", "--mount", f"type=bind,src={ca_bundle.resolve()},dst=/etc/ssl/certs/ca-certificates.crt,readonly", EVALUATION_WORKER_IMAGE,
    ]
    started = time.perf_counter()
    try:
        result = _run(command, input_text=json.dumps({"url": url}), timeout=75)
    except subprocess.TimeoutExpired:
        return None, "worker_timeout", time.perf_counter() - started
    duration = time.perf_counter() - started
    if result.returncode != 0:
        return None, "worker_container_error", duration
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None, "worker_malformed_result", duration
    if not isinstance(payload, dict):
        return None, "worker_reported_error", duration
    if payload.get("status") != "success":
        message = payload.get("message")
        if isinstance(message, str) and message:
            return None, f"worker_reported_error:{message}", duration
        return None, "worker_reported_error", duration
    required = ("final_url", "html", "screenshot_base64")
    if any(not isinstance(payload.get(field), str) or not payload[field] for field in required):
        return None, "worker_missing_output", duration
    try:
        base64.b64decode(payload["screenshot_base64"], validate=True)
    except Exception:
        return None, "worker_invalid_screenshot", duration
    return payload, None, duration


def _verdict(score: int) -> str:
    if score >= HIGH_RISK_THRESHOLD:
        return "High Risk"
    if score >= SCREENING_THRESHOLD:
        return "Medium Risk"
    return "Low Risk"


def _explanation(case: dict[str, str], predicted: str, url_signals: list[str], html_signals: list[str], score: int) -> str:
    signals = url_signals + html_signals
    if case["expected_label"] == "benign":
        return f"Frozen score reached {score} from: {' | '.join(signals) or 'no recorded signals'}"
    return f"Frozen score remained {score}; absent/insufficient signals: {' | '.join(signals) or 'none'}"


def _write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _cleanup() -> None:
    _remove_if_present(FIXTURE_CONTAINER)
    _remove_if_present(PROXY_CONTAINER)
    _remove_if_present(NETWORK, network=True)
    _run(["docker", "image", "rm", "-f", EVALUATION_WORKER_IMAGE], timeout=30)
    shutil.rmtree(TLS, ignore_errors=True)


def main() -> None:
    cases, integrity = _verify_inputs()
    # A preflight may have created this otherwise empty directory before an
    # infrastructure failure. ``summary.json`` above is the immutable-result
    # guard; allowing the empty directory avoids treating that failure as data.
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    ca_bundle: Path | None = None
    try:
        ca_bundle = _create_tls_material()
        _start_topology(ca_bundle)
        # Health preflight renders a non-labelled page only; no detector is called.
        health, error, _ = _run_worker("https://h5fixtures:8443/health.html", ca_bundle, "health")
        if health is not None or error != "worker_reported_error":
            # health.html is intentionally absent; a browser-generated 404 page still proves HTTPS navigation,
            # rendering, HTML extraction, and screenshot capture. It must be a successful worker response.
            if health is None:
                raise RuntimeError(f"Sandbox health preflight failed: {error}")
        else:
            raise RuntimeError(f"Sandbox health preflight failed: {error}")

        for case in cases:
            worker, error, duration = _run_worker(case["synthetic_url"], ca_bundle, case["case_id"])
            row: dict[str, Any] = {
                "case_id": case["case_id"], "expected_label": case["expected_label"], "synthetic_url": case["synthetic_url"],
                "fixture": case["fixture"], "navigation_success": False, "render_success": False,
                "html_extraction_success": False, "screenshot_success": False, "url_score": "", "url_signals": "",
                "html_score": "", "html_signals": "", "combined_score": "", "verdict": "", "predicted_label": "",
                "correct": "", "execution_duration_seconds": f"{duration:.3f}", "execution_error_stage": "", "execution_error_category": "",
            }
            if worker is None:
                row["execution_error_stage"] = "sandbox_worker"
                row["execution_error_category"] = error or "unknown"
                failures.append({"case_id": case["case_id"], "stage": "sandbox_worker", "error_category": error or "unknown", "cause": "evaluation_infrastructure_or_worker"})
            else:
                html_result = detect_phishing(worker["html"], page_url=worker["final_url"])
                url_result = analyze_url(case["synthetic_url"], worker["final_url"])
                score = int(url_result["score"]) + int(html_result["score"])
                predicted = "phishing" if score >= SCREENING_THRESHOLD else "benign"
                row.update({
                    "navigation_success": True, "render_success": True, "html_extraction_success": True, "screenshot_success": True,
                    "url_score": url_result["score"], "url_signals": " | ".join(url_result["reasons"]),
                    "html_score": html_result["score"], "html_signals": " | ".join(html_result["reasons"]),
                    "combined_score": score, "verdict": _verdict(score), "predicted_label": predicted,
                    "correct": predicted == case["expected_label"],
                })
            results.append(row)
    finally:
        _cleanup()

    successful = [row for row in results if row["predicted_label"]]
    if not successful:
        raise RuntimeError("No cases completed the rendered sandbox path; no benchmark metrics were produced.")
    tp = sum(row["expected_label"] == "phishing" and row["predicted_label"] == "phishing" for row in successful)
    tn = sum(row["expected_label"] == "benign" and row["predicted_label"] == "benign" for row in successful)
    fp = sum(row["expected_label"] == "benign" and row["predicted_label"] == "phishing" for row in successful)
    fn = sum(row["expected_label"] == "phishing" and row["predicted_label"] == "benign" for row in successful)
    total = len(successful)
    metric = lambda value: round(value * 100, 2)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    specificity = tn / (tn + fp) if tn + fp else 0.0
    summary = {
        "benchmark_name": "Independent Synthetic Rendered-Page / Sandbox Benchmark",
        "scope": "Synthetic, local, browser-rendered benchmark only; not live or population-level phishing accuracy.",
        "binary_policy": "combined score >= 10 maps to phishing; combined score < 10 maps to benign.",
        "total_manifest_cases": len(cases), "successful_cases": total, "benign_successful": sum(r["expected_label"] == "benign" for r in successful),
        "phishing_successful": sum(r["expected_label"] == "phishing" for r in successful), "execution_failures": len(failures),
        "navigation_success_rate_percent": metric(sum(bool(r["navigation_success"]) for r in results) / len(cases)),
        "render_success_rate_percent": metric(sum(bool(r["render_success"]) for r in results) / len(cases)),
        "html_extraction_success_rate_percent": metric(sum(bool(r["html_extraction_success"]) for r in results) / len(cases)),
        "screenshot_success_rate_percent": metric(sum(bool(r["screenshot_success"]) for r in results) / len(cases)),
        "confusion_matrix": {"TP": tp, "TN": tn, "FP": fp, "FN": fn},
        "accuracy_percent": metric((tp + tn) / total), "precision_percent": metric(precision), "recall_percent": metric(recall),
        "specificity_percent": metric(specificity), "fpr_percent": metric(fp / (fp + tn) if fp + tn else 0.0),
        "fnr_percent": metric(fn / (fn + tp) if fn + tp else 0.0), "f1_percent": metric(2 * precision * recall / (precision + recall) if precision + recall else 0.0),
        "privacy": "Screenshots were verified in memory and were not written to user history, MongoDB, or the normal screenshot directory. Evaluation containers, TLS keys, and network were removed after execution.",
    }
    result_fields = list(results[0])
    _write_csv(EVIDENCE / "results.csv", results, result_fields)
    _write_csv(EVIDENCE / "execution_failures.csv", failures, ["case_id", "stage", "error_category", "cause"])
    _write_csv(EVIDENCE / "confusion_matrix.csv", [{"actual": "phishing", "predicted_phishing": tp, "predicted_benign": fn}, {"actual": "benign", "predicted_phishing": fp, "predicted_benign": tn}], ["actual", "predicted_phishing", "predicted_benign"])
    errors = []
    for row in successful:
        if row["correct"] is False:
            errors.append({"case_id": row["case_id"], "expected_label": row["expected_label"], "predicted_label": row["predicted_label"], "url_score": row["url_score"], "url_signals": row["url_signals"], "html_score": row["html_score"], "html_signals": row["html_signals"], "combined_score": row["combined_score"], "likely_explanation": _explanation(row, row["predicted_label"], row["url_signals"].split(" | ") if row["url_signals"] else [], row["html_signals"].split(" | ") if row["html_signals"] else [], int(row["combined_score"]))})
    (EVIDENCE / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    (EVIDENCE / "error_analysis.json").write_text(json.dumps({"false_positive_or_false_negative_cases": errors, "execution_failures": failures}, indent=2) + "\n", encoding="utf-8")
    integrity["after_hashes"] = {path: _sha256(Path(path)) for path in EXPECTED_HASHES}
    integrity["worker_image"] = WORKER_IMAGE
    integrity["evaluation_worker_image"] = EVALUATION_WORKER_IMAGE
    integrity["evaluation_worker_change"] = "One-day local CA added to the system trust store only; /app/worker.py and its entry point are inherited unchanged from qrshield-sandbox-worker:latest."
    integrity["proxy_image"] = PROXY_IMAGE
    integrity["topology"] = "Dedicated internal-only Docker network; fixture-only TLS proxy; no egress network attachment."
    integrity["production_code_changed_by_benchmark"] = False
    (EVIDENCE / "integrity.json").write_text(json.dumps(integrity, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
