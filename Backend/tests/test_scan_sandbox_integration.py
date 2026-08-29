import base64
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

# Avoid constructing the production MongoDB client while importing the route.
# Each test patches main.scan_collection with its own mock collection.
sys.modules["database"] = SimpleNamespace(scan_collection=Mock())

import main
from security.url_validator import URLValidationError
from services.sandbox_runner import SandboxExecutionError


ORIGINAL_URL = "https://example.com"
FINAL_URL = "https://www.example.com/landing"
PNG_BYTES = b"\x89PNG\r\n\x1a\nscan-image"


def test_h3b2_screening_and_high_risk_boundaries():
    assert main._risk_verdict(main.SCREENING_THRESHOLD - 1) == "Low Risk"
    assert main._risk_verdict(main.SCREENING_THRESHOLD) == "Medium Risk"
    assert main._risk_verdict(69) == "Medium Risk"
    assert main._risk_verdict(70) == "High Risk"


def sandbox_success(**overrides):
    result = {
        "status": "success",
        "final_url": FINAL_URL,
        "title": "Example Domain",
        "html": "<html><body><form></form></body></html>",
        "screenshot_base64": base64.b64encode(PNG_BYTES).decode("ascii"),
    }
    result.update(overrides)
    return result


def scan_request():
    return main.URLRequest(url=ORIGINAL_URL)


def setup_successful_scan(tmp_path: Path, insert_one=None):
    collection = Mock()
    collection.insert_one.side_effect = insert_one
    patches = patch.multiple(
        main,
        SCREENSHOT_DIRECTORY=tmp_path,
        validate_public_url=Mock(side_effect=lambda url: url),
        run_sandbox=Mock(return_value=sandbox_success()),
        detect_phishing=Mock(return_value={"score": 30, "reasons": ["HTML finding"]}),
        analyze_url=Mock(return_value={"score": 15, "verdict": "SAFE", "reasons": ["URL finding"]}),
        check_url_virustotal=Mock(return_value={"status": "success", "malicious": 0}),
        scan_collection=collection,
    )
    return patches, collection


def test_successful_sandbox_scan_preserves_response_and_persists_screenshot(tmp_path):
    patches, collection = setup_successful_scan(tmp_path)
    with patches:
        response = main.scan_url(scan_request())

    assert set(response) == {
        "status",
        "original_url",
        "final_url",
        "title",
        "screenshot",
        "risk_score",
        "verdict",
        "reasons",
        "virustotal",
    }
    assert response["status"] == "success"
    assert response["original_url"] == ORIGINAL_URL
    assert response["final_url"] == FINAL_URL
    assert response["verdict"] == "Medium Risk"
    assert response["risk_score"] == 45
    assert (tmp_path / response["screenshot"].rsplit("/", 1)[1]).read_bytes() == PNG_BYTES

    stored_document = collection.insert_one.call_args.args[0]
    assert set(stored_document) == set(response) - {"status"}
    assert stored_document["screenshot"] == response["screenshot"]


def test_initial_url_rejection_does_not_start_sandbox_or_store_scan():
    collection = Mock()
    with (
        patch.object(main, "validate_public_url", side_effect=URLValidationError("blocked")),
        patch.object(main, "run_sandbox") as run_sandbox,
        patch.object(main, "scan_collection", collection),
    ):
        response = main.scan_url(scan_request())

    assert response == {"status": "error", "message": "URL is not allowed for analysis."}
    run_sandbox.assert_not_called()
    collection.insert_one.assert_not_called()


def test_sandbox_failure_does_not_store_scan():
    collection = Mock()
    with (
        patch.object(main, "validate_public_url", side_effect=lambda url: url),
        patch.object(main, "run_sandbox", side_effect=SandboxExecutionError("timeout")),
        patch.object(main, "scan_collection", collection),
    ):
        response = main.scan_url(scan_request())

    assert response == {"status": "error", "message": "Sandbox analysis could not be completed."}
    collection.insert_one.assert_not_called()


def test_redirect_to_rejected_final_url_does_not_store_scan(tmp_path):
    collection = Mock()
    with (
        patch.object(
            main,
            "validate_public_url",
            side_effect=[ORIGINAL_URL, URLValidationError("private redirect")],
        ),
        patch.object(main, "run_sandbox", return_value=sandbox_success()),
        patch.object(main, "SCREENSHOT_DIRECTORY", tmp_path),
        patch.object(main, "scan_collection", collection),
    ):
        response = main.scan_url(scan_request())

    assert response == {"status": "error", "message": "URL is not allowed for analysis."}
    assert list(tmp_path.iterdir()) == []
    collection.insert_one.assert_not_called()


def test_malformed_sandbox_screenshot_does_not_persist_or_store(tmp_path):
    collection = Mock()
    with (
        patch.object(main, "validate_public_url", side_effect=lambda url: url),
        patch.object(main, "run_sandbox", return_value=sandbox_success(screenshot_base64="not-base64")),
        patch.object(main, "SCREENSHOT_DIRECTORY", tmp_path),
        patch.object(main, "scan_collection", collection),
    ):
        response = main.scan_url(scan_request())

    assert response == {"status": "error", "message": "Sandbox screenshot could not be processed."}
    assert list(tmp_path.iterdir()) == []
    collection.insert_one.assert_not_called()


def test_screenshot_is_removed_if_later_storage_fails(tmp_path):
    patches, _collection = setup_successful_scan(tmp_path, insert_one=RuntimeError("database unavailable"))
    with patches:
        response = main.scan_url(scan_request())

    assert response == {"status": "error", "message": "Scan analysis could not be completed."}
    assert list(tmp_path.iterdir()) == []
