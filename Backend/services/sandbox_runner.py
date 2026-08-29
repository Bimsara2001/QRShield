"""Trusted controller for one short-lived QRShield browser sandbox.

The runner intentionally has no FastAPI, database, scoring, VirusTotal, or
screenshot-persistence responsibility. It transfers one validated URL to a
single Docker worker and returns the worker's validated collection result.
"""

from __future__ import annotations

import json
import logging
import subprocess
import uuid
from typing import Any

from security.url_validator import validate_public_url


LOGGER = logging.getLogger(__name__)

SANDBOX_IMAGE = "qrshield-sandbox-worker:latest"
SANDBOX_NETWORK = "qrshield-worker-isolated"
SANDBOX_PROXY_CONTAINER = "qrshield-egress-proxy"
SANDBOX_PROXY_EGRESS_NETWORK = "qrshield-proxy-egress"
SANDBOX_PROXY_URL = "http://qrshield-egress-proxy:3128"
SANDBOX_TIMEOUT_SECONDS = 75
CLEANUP_TIMEOUT_SECONDS = 10
INFRASTRUCTURE_TIMEOUT_SECONDS = 10
SANDBOX_TMPFS = "/tmp:rw,nosuid,nodev,size=256m"
# A full-page PNG is base64 encoded in the worker response. 32 MiB leaves room
# for ordinary pages while bounding accepted output. This is a post-capture
# check: subprocess.run buffers output before it can be checked, so a future
# hardening stage may need streaming output limits for stricter RAM protection.
MAX_WORKER_STDOUT_BYTES = 32 * 1024 * 1024


class SandboxExecutionError(RuntimeError):
    """Raised when Docker or the isolated worker cannot complete a scan."""


def _container_name() -> str:
    return f"qrshield-scan-{uuid.uuid4()}"


def _docker_run_command(container_name: str) -> list[str]:
    """Return the fixed, per-scan Docker invocation without target data."""
    return [
        "docker",
        "run",
        "--name",
        container_name,
        "--rm",
        "--init",
        "-i",
        "--network",
        SANDBOX_NETWORK,
        "-e",
        f"QRSHIELD_EGRESS_PROXY={SANDBOX_PROXY_URL}",
        "--read-only",
        "--tmpfs",
        SANDBOX_TMPFS,
        "--cpus=1",
        "--memory=1g",
        "--pids-limit=256",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--shm-size=256m",
        SANDBOX_IMAGE,
    ]


def _infrastructure_error(detail: str) -> SandboxExecutionError:
    LOGGER.warning("Secure sandbox infrastructure check failed: %s", detail)
    return SandboxExecutionError("Secure sandbox infrastructure is unavailable.")


def _inspect_docker_json(command: list[str], label: str) -> Any:
    """Run a fixed Docker inspect command and parse its JSON output safely."""
    try:
        completed = subprocess.run(
            command,
            text=True,
            encoding="utf-8",
            capture_output=True,
            timeout=INFRASTRUCTURE_TIMEOUT_SECONDS,
            check=False,
            shell=False,
        )
    except FileNotFoundError as exc:
        raise _infrastructure_error("Docker executable unavailable") from exc
    except (subprocess.TimeoutExpired, OSError) as exc:
        raise _infrastructure_error(f"Docker {label} inspection failed") from exc

    if completed.returncode != 0:
        raise _infrastructure_error(f"Docker {label} is unavailable")

    try:
        return json.loads(completed.stdout)
    except (TypeError, json.JSONDecodeError) as exc:
        raise _infrastructure_error(f"Docker {label} returned invalid JSON") from exc


def _ensure_secure_infrastructure() -> None:
    """Fail closed unless the pre-provisioned proxy topology is ready.

    This intentionally verifies only existing resources. It never creates a
    network, starts/recreates the proxy, or builds an image per scan.
    """
    network_data = _inspect_docker_json(
        ["docker", "network", "inspect", SANDBOX_NETWORK],
        "isolated network",
    )
    if not isinstance(network_data, list) or not network_data:
        raise _infrastructure_error("isolated network inspect was empty")

    network = network_data[0]
    options = network.get("Options", {}) if isinstance(network, dict) else {}
    if (
        not isinstance(network, dict)
        or network.get("Internal") is not True
        or options.get("com.docker.network.bridge.gateway_mode_ipv4") != "isolated"
    ):
        raise _infrastructure_error("isolated network configuration is unsafe")

    proxy_data = _inspect_docker_json(
        ["docker", "inspect", SANDBOX_PROXY_CONTAINER],
        "egress proxy",
    )
    if not isinstance(proxy_data, list) or not proxy_data or not isinstance(proxy_data[0], dict):
        raise _infrastructure_error("egress proxy inspect was empty")

    proxy = proxy_data[0]
    if proxy.get("State", {}).get("Running") is not True:
        raise _infrastructure_error("egress proxy is not running")

    memberships = proxy.get("NetworkSettings", {}).get("Networks", {})
    if not isinstance(memberships, dict) or {
        SANDBOX_NETWORK,
        SANDBOX_PROXY_EGRESS_NETWORK,
    } - memberships.keys():
        raise _infrastructure_error("egress proxy network memberships are incomplete")


def _cleanup_container(container_name: str) -> None:
    """Force-remove only this run's known container as a cleanup fallback."""
    cleanup_command = ["docker", "rm", "-f", container_name]
    LOGGER.info("Sandbox cleanup attempted: %s", container_name)

    try:
        completed = subprocess.run(
            cleanup_command,
            text=True,
            encoding="utf-8",
            capture_output=True,
            timeout=CLEANUP_TIMEOUT_SECONDS,
            check=False,
            shell=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        LOGGER.warning("Sandbox cleanup could not run for %s: %s", container_name, type(exc).__name__)
        return

    stderr = completed.stderr if isinstance(completed.stderr, str) else ""
    if completed.returncode != 0 and "no such container" not in stderr.lower():
        LOGGER.warning("Sandbox cleanup failed for %s", container_name)


def _worker_error_from_return_code(stderr: str) -> SandboxExecutionError:
    diagnostic = stderr.lower()
    image_missing_markers = (
        "unable to find image",
        "pull access denied",
        "repository does not exist",
        "image not found",
    )
    if any(marker in diagnostic for marker in image_missing_markers):
        return SandboxExecutionError("Sandbox worker image is unavailable.")
    return SandboxExecutionError("Docker failed to run the sandbox worker.")


def _parse_worker_result(stdout: str) -> dict[str, str]:
    if not stdout.strip():
        raise SandboxExecutionError("Sandbox worker returned no result.")

    if len(stdout.encode("utf-8")) > MAX_WORKER_STDOUT_BYTES:
        raise SandboxExecutionError("Sandbox worker result exceeded the allowed size.")

    try:
        result = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise SandboxExecutionError("Sandbox worker returned malformed JSON.") from exc

    if not isinstance(result, dict) or not isinstance(result.get("status"), str):
        raise SandboxExecutionError("Sandbox worker returned an invalid result.")

    if result["status"] == "error":
        raise SandboxExecutionError("Sandbox worker reported an analysis failure.")

    if result["status"] != "success":
        raise SandboxExecutionError("Sandbox worker returned an invalid status.")

    required_fields = ("final_url", "title", "html", "screenshot_base64")
    for field in required_fields:
        if field not in result:
            raise SandboxExecutionError("Sandbox worker result is missing required data.")
        if not isinstance(result[field], str):
            raise SandboxExecutionError("Sandbox worker result contains invalid data.")

    if not result["final_url"] or not result["screenshot_base64"]:
        raise SandboxExecutionError("Sandbox worker result contains empty required data.")

    return result


def run_sandbox(url: str) -> dict[str, str]:
    """Run one worker container and return its validated collection result.

    ``url`` is expected to have been validated by the caller. It is validated
    again here as defense in depth before Docker is started.
    """
    validated_url = validate_public_url(url)
    container_name = _container_name()

    try:
        _ensure_secure_infrastructure()
        command = _docker_run_command(container_name)
        worker_input = json.dumps({"url": validated_url})
        LOGGER.info("Sandbox started: %s", container_name)
        try:
            completed = subprocess.run(
                command,
                input=worker_input,
                text=True,
                encoding="utf-8",
                capture_output=True,
                timeout=SANDBOX_TIMEOUT_SECONDS,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired as exc:
            # subprocess.run kills and waits for its child on timeout. The
            # finally block still force-removes the named Docker container in
            # case the Docker client was interrupted before daemon cleanup.
            LOGGER.warning("Sandbox timed out: %s", container_name)
            raise SandboxExecutionError("Sandbox analysis timed out.") from exc
        except FileNotFoundError as exc:
            raise SandboxExecutionError("Docker is unavailable.") from exc
        except OSError as exc:
            raise SandboxExecutionError("Docker could not start the sandbox worker.") from exc

        stdout = completed.stdout if isinstance(completed.stdout, str) else ""
        stderr = completed.stderr if isinstance(completed.stderr, str) else ""
        if completed.returncode != 0:
            raise _worker_error_from_return_code(stderr)

        result = _parse_worker_result(stdout)
        LOGGER.info("Sandbox completed: %s", container_name)
        return result
    finally:
        _cleanup_container(container_name)
