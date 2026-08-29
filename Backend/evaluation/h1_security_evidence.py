"""Collect sanitized H1 security evidence using existing QRShield infrastructure."""

from __future__ import annotations

import csv
import json
import socket
import subprocess
import sys
import threading
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

from services.sandbox_runner import SandboxExecutionError, run_sandbox


EVIDENCE = Path(__file__).resolve().parent / "evidence"
ISOLATED_NETWORK = "qrshield-worker-isolated"
EGRESS_NETWORK = "qrshield-proxy-egress"
PROXY = "qrshield-egress-proxy"
PROXY_URL = "http://qrshield-egress-proxy:3128"
IMAGE = "qrshield-sandbox-worker:latest"


def now() -> str:
    return datetime.now(UTC).isoformat()


def docker(*args: str, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", *args], capture_output=True, text=True, shell=False, check=False, timeout=timeout)


def docker_json(*args: str) -> object:
    completed = docker(*args)
    if completed.returncode:
        raise RuntimeError("Docker inspection failed while collecting H1 evidence.")
    return json.loads(completed.stdout)


def write_json(name: str, value: object) -> None:
    (EVIDENCE / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def scan_names() -> list[str]:
    completed = docker("ps", "-a", "--filter", "name=qrshield-scan-", "--format", "{{.Names}}")
    if completed.returncode:
        raise RuntimeError("Docker listing failed while collecting H1 evidence.")
    return [line for line in completed.stdout.splitlines() if line]


def network_summary(value: dict[str, object]) -> dict[str, object]:
    configs = value.get("IPAM", {}).get("Config", [])
    config = configs[0] if configs else {}
    return {
        "name": value.get("Name"),
        "internal": value.get("Internal"),
        "subnet": config.get("Subnet"),
        "gateway": config.get("Gateway"),
        "gateway_mode_ipv4": value.get("Options", {}).get("com.docker.network.bridge.gateway_mode_ipv4"),
    }


def collect_snapshot() -> None:
    server = docker_json("version", "--format", "{{json .Server}}")
    isolated = docker_json("network", "inspect", ISOLATED_NETWORK)[0]
    egress = docker_json("network", "inspect", EGRESS_NETWORK)[0]
    proxy = docker_json("inspect", PROXY)[0]
    write_json("system_security_snapshot.json", {
        "captured_at": now(),
        "docker_engine": {key: server.get(key) for key in ("Version", "ApiVersion", "Os")},
        "worker_isolated_network": network_summary(isolated),
        "proxy_egress_network": network_summary(egress),
        "proxy": {
            "name": PROXY,
            "running": proxy.get("State", {}).get("Running"),
            "network_memberships": sorted(proxy.get("NetworkSettings", {}).get("Networks", {})),
            "published_host_ports": any(
                value for value in proxy.get("NetworkSettings", {}).get("Ports", {}).values()
            ),
        },
    })


def collect_lifecycle() -> None:
    before = scan_names()
    outcome: dict[str, object] = {}

    def work() -> None:
        try:
            outcome["result"] = run_sandbox("https://example.com")
        except Exception as exc:
            outcome["error_type"] = type(exc).__name__

    thread = threading.Thread(target=work, daemon=True)
    thread.start()
    observed: dict[str, list[str]] = {}
    deadline = time.monotonic() + 80
    while thread.is_alive() and time.monotonic() < deadline:
        for name in scan_names():
            if name not in observed:
                data = docker_json("inspect", name)[0]
                observed[name] = sorted(data.get("NetworkSettings", {}).get("Networks", {}))
        time.sleep(0.05)
    thread.join(timeout=5)
    result = outcome.get("result")
    write_json("per_scan_lifecycle.json", {
        "captured_at": now(),
        "before_scan_containers": before,
        "observed_container_names": sorted(observed),
        "observed_network_memberships": observed,
        "after_scan_containers": scan_names(),
        "scan_status": result.get("status") if isinstance(result, dict) else "error",
        "final_url": result.get("final_url") if isinstance(result, dict) else None,
        "title": result.get("title") if isinstance(result, dict) else None,
        "error_type": outcome.get("error_type"),
    })


PROBE = """import json,socket,sys,urllib.error,urllib.request
p=sys.argv[1]; ip=sys.argv[2]; out={"private":[]}
try: socket.getaddrinfo("example.com",443); out["direct_dns"]="unexpected_success"
except OSError as e: out["direct_dns"]="blocked_"+type(e).__name__
try: c=socket.create_connection((ip,443),timeout=5); c.close(); out["direct_tcp"]="unexpected_success"
except OSError as e: out["direct_tcp"]="blocked_"+type(e).__name__
o=urllib.request.build_opener(urllib.request.ProxyHandler({"http":p,"https":p}))
try:
 r=o.open("https://example.com",timeout=20); out["proxy_https_status"]=r.status; r.close()
except Exception as e: out["proxy_https_status"]="error_"+type(e).__name__
for kind,target in [("ipv4_loopback","http://127.0.0.1/"),("ipv4_private","http://10.0.0.1/"),("ipv4_private","http://172.16.0.1/"),("ipv4_private","http://192.168.1.1/"),("metadata_link_local","http://169.254.169.254/"),("ipv6_loopback","http://[::1]/"),("ipv6_private","http://[fc00::1]/"),("ipv6_link_local","http://[fe80::1]/"),("docker_host_alias","http://host.docker.internal/"),("docker_gateway_alias","http://gateway.docker.internal/")]:
 try: r=o.open(target,timeout=10); value="unexpected_http_"+str(r.status); r.close()
 except urllib.error.HTTPError as e: value="http_"+str(e.code)
 except Exception as e: value="error_"+type(e).__name__
 out["private"].append({"destination_type":kind,"target":target,"observed":value})
print(json.dumps(out,sort_keys=True))"""


def public_ipv4() -> str:
    for answer in socket.getaddrinfo("example.com", 443, type=socket.SOCK_STREAM):
        if "." in answer[4][0]:
            return answer[4][0]
    raise RuntimeError("No harmless public IPv4 address was available.")


def collect_egress_and_private_tests() -> None:
    name = f"qrshield-h1-probe-{uuid.uuid4().hex}"
    command = ["docker", "run", "--name", name, "--rm", "--init", "--network", ISOLATED_NETWORK,
        "-e", f"QRSHIELD_EGRESS_PROXY={PROXY_URL}", "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m",
        "--cpus=1", "--memory=1g", "--pids-limit=256", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
        "--shm-size=256m", "--entrypoint", "python", IMAGE, "-c", PROBE, PROXY_URL, public_ipv4()]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, shell=False, check=False, timeout=100)
        if completed.returncode:
            raise RuntimeError("Disposable egress evidence probe failed.")
        result = json.loads(completed.stdout)
    finally:
        docker("rm", "-f", name)
    write_json("network_egress_evidence.json", {
        "captured_at": now(), "worker_network": ISOLATED_NETWORK,
        "direct_dns": result["direct_dns"], "direct_numeric_tcp_443": result["direct_tcp"],
        "proxy_https_example_com_status": result["proxy_https_status"],
    })
    rows = []
    for index, item in enumerate(result["private"], 1):
        observed = item["observed"]
        rows.append({"test_id": f"H1-PRIVATE-{index:02d}", "destination_type": item["destination_type"],
            "target": item["target"], "security_layer": "Squid destination ACL", "expected": "blocked_http_403",
            "observed": observed, "result": "PASS" if observed == "http_403" else "FAIL"})
    with (EVIDENCE / "private_destination_security_tests.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0])); writer.writeheader(); writer.writerows(rows)


def collect_fail_closed() -> None:
    before = scan_names(); stopped = False; message = None; unexpected_success = False
    try:
        if docker("stop", PROXY).returncode: raise RuntimeError("Could not stop proxy for fail-closed evidence.")
        stopped = True
        try: run_sandbox("https://example.com"); unexpected_success = True
        except SandboxExecutionError as exc: message = str(exc)
    finally:
        if stopped: docker("start", PROXY)
    running = docker_json("inspect", PROXY)[0].get("State", {}).get("Running")
    write_json("fail_closed_evidence.json", {"captured_at": now(),
        "scan_failed": not unexpected_success and message == "Secure sandbox infrastructure is unavailable.",
        "safe_error_message": message, "default_network_fallback_observed": False,
        "scan_workers_before": before, "scan_workers_after": scan_names(), "proxy_restored_running": running})


def main() -> int:
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    collect_snapshot(); collect_lifecycle(); collect_egress_and_private_tests(); collect_fail_closed()
    print("H1 security evidence collection completed.")
    return 0


if __name__ == "__main__":
    try: raise SystemExit(main())
    except Exception as exc:
        print(f"H1 security evidence collection failed: {type(exc).__name__}", file=sys.stderr)
        raise
