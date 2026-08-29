import base64
import hashlib
import socket
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from fastapi import HTTPException

# Do not construct the production MongoDB client while importing the route.
sys.modules["database"] = SimpleNamespace(scan_collection=Mock())

import main


FROZEN_SOURCE_HASHES = {
    "analyzer/risk_engine.py": "e837e453313a5507ac75f598884c929f929a08ca1a560d50a9cbc9919c1c00e1",
    "detectors/phishing_detector.py": "1bffa7d2099ff9411bca4035334033bcee1308fec31a367d71c962f5c27a628a",
}
PNG_BYTES = b"\x89PNG\r\n\x1a\ncontrolled-test"


@pytest.fixture(autouse=True)
def enable_controlled_ui_test(monkeypatch):
    monkeypatch.setenv(main.CONTROLLED_UI_TEST_ENV, "1")


def test_allowlisted_fixture_returns_result_screen_contract():
    response = main.controlled_scan(
        main.ControlledScanRequest(fixture="fake_banking_login")
    )

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
    assert response["title"] == "TEST ONLY — inert fixture: fake_banking_login"
    assert response["screenshot"] == "/test/static/controlled-placeholder.png"
    assert response["risk_score"] == 140
    assert response["verdict"] == "High Risk"
    assert response["virustotal"] == {
        "status": "test",
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "verdict": "NOT_QUERIED",
    }


@pytest.mark.parametrize(
    "fixture",
    ["unknown_fixture", "external_credential_form", "../../main.py"],
)
def test_unknown_or_path_traversal_fixture_is_rejected(fixture):
    with pytest.raises(HTTPException) as error:
        main.controlled_scan(main.ControlledScanRequest(fixture=fixture))

    assert error.value.status_code == 400


def test_controlled_scan_makes_no_network_or_production_service_calls(monkeypatch):
    def network_access(*_args, **_kwargs):
        raise AssertionError("Controlled UI scan must not open a network connection")

    monkeypatch.setattr(socket.socket, "connect", network_access)
    monkeypatch.setattr(main, "run_sandbox", Mock(side_effect=AssertionError))
    monkeypatch.setattr(main, "check_url_virustotal", Mock(side_effect=AssertionError))
    monkeypatch.setattr(main, "scan_collection", Mock(side_effect=AssertionError))

    response = main.controlled_scan(
        main.ControlledScanRequest(fixture="fake_banking_login")
    )

    assert response["status"] == "success"
    main.run_sandbox.assert_not_called()
    main.check_url_virustotal.assert_not_called()
    main.scan_collection.assert_not_called()


def test_production_scan_route_still_uses_sandbox_and_virustotal(monkeypatch, tmp_path):
    sandbox_result = {
        "final_url": "https://example.com/final",
        "title": "Example",
        "html": "<html></html>",
        "screenshot_base64": base64.b64encode(PNG_BYTES).decode("ascii"),
    }
    sandbox = Mock(return_value=sandbox_result)
    virustotal = Mock(return_value={"status": "success", "malicious": 0})
    collection = Mock()

    monkeypatch.setattr(main, "SCREENSHOT_DIRECTORY", tmp_path)
    monkeypatch.setattr(main, "validate_public_url", lambda url: url)
    monkeypatch.setattr(main, "run_sandbox", sandbox)
    monkeypatch.setattr(main, "detect_phishing", lambda *_args, **_kwargs: {"score": 0, "reasons": []})
    monkeypatch.setattr(main, "analyze_url", lambda *_args: {"score": 0, "reasons": [], "verdict": "SAFE"})
    monkeypatch.setattr(main, "check_url_virustotal", virustotal)
    monkeypatch.setattr(main, "scan_collection", collection)

    response = main.scan_url(main.URLRequest(url="https://example.com"))

    assert response["status"] == "success"
    sandbox.assert_called_once_with("https://example.com")
    virustotal.assert_called_once_with("https://example.com/final")
    collection.insert_one.assert_called_once()


def test_frozen_detector_and_risk_engine_hashes_are_unchanged():
    backend_root = Path(__file__).resolve().parents[1]
    hashes = {
        relative_path: hashlib.sha256(
            (backend_root / relative_path).read_bytes()
        ).hexdigest()
        for relative_path in FROZEN_SOURCE_HASHES
    }

    assert hashes == FROZEN_SOURCE_HASHES
