"""Render the dissertation-oriented H1 evidence summary from collected files."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path


EVIDENCE = Path(__file__).resolve().parent / "evidence"


def load(name: str) -> dict:
    path = EVIDENCE / name
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def main() -> int:
    snapshot = load("system_security_snapshot.json")
    lifecycle = load("per_scan_lifecycle.json")
    egress = load("network_egress_evidence.json")
    fail_closed = load("fail_closed_evidence.json")
    functional = load("functional_scan.json")
    tests = load("test_suite_result.json")
    latency = load("latency_summary.json")
    proxy = snapshot.get("proxy", {})
    isolated = snapshot.get("worker_isolated_network", {})
    lines = [
        "# QRShield H1 Security and Performance Evidence",
        "",
        f"Evidence generated: {datetime.now(UTC).isoformat()}",
        "",
        "## Architecture tested",
        "",
        "FastAPI `/scan` uses a fresh, non-root Docker worker on the internal `qrshield-worker-isolated` network. Browser traffic is sent through the persistent `qrshield-egress-proxy` on port 3128. The worker is read-only with bounded `/tmp`, CPU, memory, PID, capability, and privilege-escalation controls.",
        "",
        "## Functional result",
        "",
        f"- Status: `{functional.get('status', 'not collected')}`",
        f"- Final URL: `{functional.get('final_url', 'not collected')}`",
        f"- Title: `{functional.get('title', 'not collected')}`",
        f"- Risk/verdict: `{functional.get('risk_score', 'not collected')}` / `{functional.get('verdict', 'not collected')}`",
        f"- VirusTotal status: `{functional.get('virustotal_status', 'not collected')}`",
        f"- Screenshot HTTP status: `{functional.get('screenshot_http_status', 'not collected')}`",
        f"- MongoDB history record present: `{functional.get('mongodb_history_record_present', False)}`",
        "",
        "## Isolation and proxy result",
        "",
        f"- Isolated network internal: `{isolated.get('internal')}`; gateway mode: `{isolated.get('gateway_mode_ipv4')}`.",
        f"- Proxy running: `{proxy.get('running')}`; memberships: `{', '.join(proxy.get('network_memberships', []))}`.",
        f"- Published proxy host ports: `{proxy.get('published_host_ports')}`.",
        f"- Proxy HTTPS example.com status: `{egress.get('proxy_https_example_com_status', 'not collected')}`.",
        "",
        "## Direct-egress and private-destination result",
        "",
        f"- Worker DNS resolution: `{egress.get('direct_dns', 'not collected')}`.",
        f"- Direct numeric TCP/443: `{egress.get('direct_numeric_tcp_443', 'not collected')}`.",
        "- The private-destination CSV records the expected Squid denial for loopback, private, link-local, metadata, IPv6-local, and Docker host aliases.",
        "",
        "## Fail-closed result",
        "",
        f"- Proxy-down scan failed: `{fail_closed.get('scan_failed', False)}`.",
        f"- Safe error: `{fail_closed.get('safe_error_message', 'not collected')}`.",
        f"- Default-network fallback observed: `{fail_closed.get('default_network_fallback_observed', True)}`.",
        f"- Proxy restored running: `{fail_closed.get('proxy_restored_running', False)}`.",
        "",
        "## Per-scan lifecycle",
        "",
        f"- Containers before: `{lifecycle.get('before_scan_containers', [])}`.",
        f"- Observed worker networks: `{lifecycle.get('observed_network_memberships', {})}`.",
        f"- Containers after: `{lifecycle.get('after_scan_containers', [])}`.",
        f"- Scan status: `{lifecycle.get('scan_status', 'not collected')}`.",
        "",
        "## Test-suite result",
        "",
        f"- Passed: `{tests.get('passed', 'not collected')}`; failed: `{tests.get('failed', 'not collected')}`; duration: `{tests.get('duration_seconds', 'not collected')} seconds`.",
        "",
        "## Latency summary",
        "",
        f"- Measurements: `{latency.get('count', 'not collected')}`; successful: `{latency.get('successful_scans', 'not collected')}`; failed: `{latency.get('failed_scans', 'not collected')}`.",
        f"- Minimum / maximum: `{latency.get('minimum', 'not collected')}` / `{latency.get('maximum', 'not collected')} seconds`.",
        f"- Mean / median: `{latency.get('mean', 'not collected')}` / `{latency.get('median', 'not collected')} seconds`.",
        f"- Standard deviation: `{latency.get('standard_deviation', 'not collected')} seconds`; P90: `{latency.get('p90_nearest_rank', 'not collected')}`; P95: `{latency.get('p95_nearest_rank', 'not collected')}`.",
        "",
        "## Remaining limitations",
        "",
        "This evidence does not claim protection against Docker or host-kernel compromise, container escape, proxy compromise, or exfiltration to permitted public websites. Measurements are environment- and time-dependent; they are reproducibility evidence, not a formal security proof.",
        "",
    ]
    (EVIDENCE / "security_evaluation_summary.md").write_text("\n".join(lines), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
