import json
import subprocess
from unittest.mock import patch

import pytest

import services.sandbox_runner as sandbox_runner
from services.sandbox_runner import SandboxExecutionError, _docker_run_command, run_sandbox


URL = "https://example.com"
CONTAINER_NAME = "qrshield-scan-test-id"
ORIGINAL_READINESS_CHECK = sandbox_runner._ensure_secure_infrastructure


def success_result(**overrides):
    result = {
        "status": "success",
        "final_url": "https://example.com/landing",
        "title": "Example Domain",
        "html": "<html><body>Example</body></html>",
        "screenshot_base64": "cG5nLWJ5dGVz",
    }
    result.update(overrides)
    return result


def completed(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(args=["docker"], returncode=returncode, stdout=stdout, stderr=stderr)


def cleanup_completed():
    return completed(stderr="No such container: qrshield-scan-test-id", returncode=1)


def run_calls(worker_completed):
    return [worker_completed, cleanup_completed()]


@pytest.fixture(autouse=True)
def bypass_readiness_for_worker_execution_tests(monkeypatch):
    """Readiness has focused tests below; execution tests mock it by default."""
    monkeypatch.setattr(sandbox_runner, "_ensure_secure_infrastructure", lambda: None)


def test_docker_command_contains_required_hardening_and_no_prohibited_options():
    command = _docker_run_command(CONTAINER_NAME)

    assert "--name" in command
    assert "--rm" in command
    assert "--init" in command
    assert command.count("--network") == 1
    assert command[command.index("--network") + 1] == sandbox_runner.SANDBOX_NETWORK
    assert "-e" in command
    assert command[command.index("-e") + 1] == f"QRSHIELD_EGRESS_PROXY={sandbox_runner.SANDBOX_PROXY_URL}"
    assert "--read-only" in command
    assert "--tmpfs" in command
    assert "/tmp:rw,nosuid,nodev,size=256m" in command
    assert "--cpus=1" in command
    assert "--memory=1g" in command
    assert "--pids-limit=256" in command
    assert "--cap-drop=ALL" in command
    assert "--security-opt=no-new-privileges:true" in command
    assert "--shm-size=256m" in command

    assert "--privileged" not in command
    assert "--network=host" not in command
    assert "--network bridge" not in command
    assert "--network=bridge" not in command
    assert "--network none" not in command
    assert "--network=none" not in command
    assert sandbox_runner.SANDBOX_PROXY_EGRESS_NETWORK not in command
    assert "--ipc=host" not in command
    assert "--ipc" not in command
    assert "--no-sandbox" not in command
    assert "SYS_ADMIN" not in command
    assert "QRSHIELD_ALLOW_DIRECT_MODE=1" not in command


@patch("services.sandbox_runner.uuid.uuid4", return_value="test-id")
@patch("services.sandbox_runner.validate_public_url", return_value=URL)
@patch("services.sandbox_runner.subprocess.run")
def test_returns_valid_worker_success(mock_run, _validate_url, _uuid):
    worker = completed(stdout=json.dumps(success_result()))
    mock_run.side_effect = run_calls(worker)

    assert run_sandbox(URL) == success_result()


@patch("services.sandbox_runner.uuid.uuid4", return_value="test-id")
@patch("services.sandbox_runner.validate_public_url", return_value=URL)
@patch("services.sandbox_runner.subprocess.run")
def test_worker_utf8_result_preserves_non_ascii_text(mock_run, _validate_url, _uuid):
    multilingual = success_result(
        title="Wikipédia 日本語 සිංහල தமிழ்",
        html="<html><body>Wikipédia 日本語 සිංහල தமிழ்</body></html>",
    )
    mock_run.side_effect = run_calls(completed(stdout=json.dumps(multilingual, ensure_ascii=False)))

    result = run_sandbox(URL)

    assert result["title"] == multilingual["title"]
    assert result["html"] == multilingual["html"]
    assert mock_run.call_args_list[0].kwargs["encoding"] == "utf-8"


@patch("services.sandbox_runner.uuid.uuid4", return_value="test-id")
@patch("services.sandbox_runner.validate_public_url", return_value=URL)
@patch("services.sandbox_runner.subprocess.run")
def test_worker_error_status_raises_sandbox_error(mock_run, _validate_url, _uuid):
    mock_run.side_effect = run_calls(completed(stdout=json.dumps({"status": "error", "message": "failed"})))

    with pytest.raises(SandboxExecutionError, match="analysis failure"):
        run_sandbox(URL)


@pytest.mark.parametrize(
    "stdout, message",
    [
        ("not-json", "malformed JSON"),
        ("   ", "no result"),
    ],
)
@patch("services.sandbox_runner.uuid.uuid4", return_value="test-id")
@patch("services.sandbox_runner.validate_public_url", return_value=URL)
@patch("services.sandbox_runner.subprocess.run")
def test_rejects_invalid_worker_stdout(mock_run, _validate_url, _uuid, stdout, message):
    mock_run.side_effect = run_calls(completed(stdout=stdout))

    with pytest.raises(SandboxExecutionError, match=message):
        run_sandbox(URL)


@patch("services.sandbox_runner.uuid.uuid4", return_value="test-id")
@patch("services.sandbox_runner.validate_public_url", return_value=URL)
@patch("services.sandbox_runner.subprocess.run")
def test_nonzero_docker_exit_raises_sanitized_error(mock_run, _validate_url, _uuid):
    mock_run.side_effect = run_calls(completed(stderr="daemon returned an error", returncode=1))

    with pytest.raises(SandboxExecutionError, match="Docker failed"):
        run_sandbox(URL)


@patch("services.sandbox_runner.uuid.uuid4", return_value="test-id")
@patch("services.sandbox_runner.validate_public_url", return_value=URL)
@patch("services.sandbox_runner.subprocess.run")
def test_timeout_raises_and_attempts_cleanup(mock_run, _validate_url, _uuid):
    mock_run.side_effect = [subprocess.TimeoutExpired(cmd=["docker"], timeout=75), cleanup_completed()]

    with pytest.raises(SandboxExecutionError, match="timed out"):
        run_sandbox(URL)

    assert mock_run.call_args_list[1].args[0] == ["docker", "rm", "-f", CONTAINER_NAME]


@patch("services.sandbox_runner.uuid.uuid4", return_value="test-id")
@patch("services.sandbox_runner.validate_public_url", return_value=URL)
@patch("services.sandbox_runner.subprocess.run")
def test_missing_docker_executable_raises_and_attempts_cleanup(mock_run, _validate_url, _uuid):
    mock_run.side_effect = [FileNotFoundError(), FileNotFoundError()]

    with pytest.raises(SandboxExecutionError, match="Docker is unavailable"):
        run_sandbox(URL)

    assert mock_run.call_args_list[1].args[0] == ["docker", "rm", "-f", CONTAINER_NAME]


@pytest.mark.parametrize(
    "result, message",
    [
        (success_result(html=None), "invalid data"),
        (success_result(final_url=""), "empty required data"),
        ({"status": "success", "final_url": "https://example.com"}, "missing required data"),
    ],
)
@patch("services.sandbox_runner.uuid.uuid4", return_value="test-id")
@patch("services.sandbox_runner.validate_public_url", return_value=URL)
@patch("services.sandbox_runner.subprocess.run")
def test_rejects_missing_or_wrong_success_data(mock_run, _validate_url, _uuid, result, message):
    mock_run.side_effect = run_calls(completed(stdout=json.dumps(result)))

    with pytest.raises(SandboxExecutionError, match=message):
        run_sandbox(URL)


@patch("services.sandbox_runner.uuid.uuid4", side_effect=["first-id", "second-id"])
@patch("services.sandbox_runner.validate_public_url", return_value=URL)
@patch("services.sandbox_runner.subprocess.run")
def test_each_run_uses_a_unique_container_name(mock_run, _validate_url, _uuid):
    worker = completed(stdout=json.dumps(success_result()))
    mock_run.side_effect = [worker, cleanup_completed(), worker, cleanup_completed()]

    run_sandbox(URL)
    run_sandbox(URL)

    first_command = mock_run.call_args_list[0].args[0]
    second_command = mock_run.call_args_list[2].args[0]
    assert "qrshield-scan-first-id" in first_command
    assert "qrshield-scan-second-id" in second_command
    assert first_command != second_command


@patch("services.sandbox_runner.uuid.uuid4", return_value="test-id")
@patch("services.sandbox_runner.validate_public_url", return_value=URL)
@patch("services.sandbox_runner.subprocess.run")
def test_url_is_sent_only_through_stdin_json(mock_run, _validate_url, _uuid):
    worker = completed(stdout=json.dumps(success_result()))
    mock_run.side_effect = run_calls(worker)

    run_sandbox(URL)

    command = mock_run.call_args_list[0].args[0]
    kwargs = mock_run.call_args_list[0].kwargs
    assert URL not in command
    assert json.loads(kwargs["input"]) == {"url": URL}
    assert kwargs["shell"] is False
    assert kwargs["encoding"] == "utf-8"
    assert "--privileged" not in command
    assert command[command.index("--network") + 1] == sandbox_runner.SANDBOX_NETWORK
    assert sandbox_runner.SANDBOX_PROXY_EGRESS_NETWORK not in command
    assert "QRSHIELD_ALLOW_DIRECT_MODE=1" not in command
    assert "--ipc" not in command


def readiness_network():
    return {
        "Name": sandbox_runner.SANDBOX_NETWORK,
        "Internal": True,
        "Options": {"com.docker.network.bridge.gateway_mode_ipv4": "isolated"},
    }


def readiness_proxy(*, running=True, memberships=None):
    if memberships is None:
        memberships = {
            sandbox_runner.SANDBOX_NETWORK: {},
            sandbox_runner.SANDBOX_PROXY_EGRESS_NETWORK: {},
        }
    return {"State": {"Running": running}, "NetworkSettings": {"Networks": memberships}}


def test_readiness_accepts_existing_running_proxy_with_required_networks(monkeypatch):
    mock_run = monkeypatch.setattr(sandbox_runner.subprocess, "run", lambda *args, **kwargs: None)
    del mock_run
    calls = iter(
        [
            completed(stdout=json.dumps([readiness_network()])),
            completed(stdout=json.dumps([readiness_proxy()])),
        ]
    )
    monkeypatch.setattr(sandbox_runner.subprocess, "run", lambda *args, **kwargs: next(calls))

    ORIGINAL_READINESS_CHECK()


@pytest.mark.parametrize(
    "responses",
    [
        [completed(returncode=1)],
        [completed(stdout=json.dumps([readiness_network()])), completed(returncode=1)],
        [completed(stdout=json.dumps([readiness_network()])), completed(stdout=json.dumps([readiness_proxy(running=False)]))],
        [
            completed(stdout=json.dumps([readiness_network()])),
            completed(stdout=json.dumps([readiness_proxy(memberships={sandbox_runner.SANDBOX_PROXY_EGRESS_NETWORK: {}})])),
        ],
        [
            completed(stdout=json.dumps([readiness_network()])),
            completed(stdout=json.dumps([readiness_proxy(memberships={sandbox_runner.SANDBOX_NETWORK: {}})])),
        ],
    ],
)
def test_readiness_fails_closed_for_missing_or_unsafe_infrastructure(monkeypatch, responses):
    calls = iter(responses)
    monkeypatch.setattr(sandbox_runner.subprocess, "run", lambda *args, **kwargs: next(calls))

    with pytest.raises(SandboxExecutionError, match="Secure sandbox infrastructure"):
        ORIGINAL_READINESS_CHECK()


def test_readiness_fails_closed_when_docker_is_unavailable(monkeypatch):
    monkeypatch.setattr(sandbox_runner.subprocess, "run", lambda *args, **kwargs: (_ for _ in ()).throw(FileNotFoundError()))

    with pytest.raises(SandboxExecutionError, match="Secure sandbox infrastructure"):
        ORIGINAL_READINESS_CHECK()
