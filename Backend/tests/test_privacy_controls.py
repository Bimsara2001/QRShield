import os
import time
import uuid
from pathlib import Path

import pytest
from fastapi import HTTPException

import main
from threat_intel import virustotal


class HistoryCollection:
    def __init__(self, records):
        self.records = list(records)
        self.delete_calls = 0

    def find(self, *_args, **_kwargs):
        return list(self.records)

    def delete_many(self, _query):
        self.delete_calls += 1
        self.records = []


def screenshot_name():
    return f"{uuid.uuid4()}.png"


def screenshot_url(name):
    return f"http://localhost:8000/screenshots/{name}"


def test_missing_virustotal_secret_disables_optional_integration(monkeypatch):
    monkeypatch.delenv(virustotal.API_KEY_ENV, raising=False)

    result = virustotal.check_url_virustotal("https://example.com")

    assert result == {
        "status": "disabled",
        "message": "VirusTotal integration is not configured",
    }


def test_sensitive_route_token_requires_configuration_and_matching_value(monkeypatch):
    monkeypatch.delenv(main.API_TOKEN_ENV, raising=False)
    with pytest.raises(HTTPException) as unavailable:
        main.require_sensitive_route_token(None)
    assert unavailable.value.status_code == 503

    monkeypatch.setenv(main.API_TOKEN_ENV, "test-route-token")
    with pytest.raises(HTTPException) as unauthorized:
        main.require_sensitive_route_token("wrong-token")
    assert unauthorized.value.status_code == 401

    assert main.require_sensitive_route_token("test-route-token") is None


def test_screenshot_route_registers_token_guard_and_serves_authorized_handler(monkeypatch, tmp_path):
    name = screenshot_name()
    (tmp_path / name).write_bytes(b"\x89PNG\r\n\x1a\nprivacy-test")
    monkeypatch.setattr(main, "SCREENSHOT_DIRECTORY", tmp_path)
    monkeypatch.setenv(main.API_TOKEN_ENV, "test-route-token")
    route = next(route for route in main.app.routes if route.path == "/screenshots/{screenshot_name}")

    assert route.dependant.dependencies[0].call is main.require_sensitive_route_token
    with pytest.raises(HTTPException) as unauthorized:
        main.require_sensitive_route_token("wrong-token")
    assert unauthorized.value.status_code == 401

    assert main.require_sensitive_route_token("test-route-token") is None
    response = main.get_screenshot(name, None)
    assert response.headers["cache-control"] == "no-store"
    assert response.path == tmp_path / name


def test_clear_history_removes_owned_screenshots_and_ignores_missing_or_unsafe_references(monkeypatch, tmp_path):
    screenshot_directory = tmp_path / "screenshots"
    screenshot_directory.mkdir()
    owned_name = screenshot_name()
    owned_path = screenshot_directory / owned_name
    owned_path.write_bytes(b"owned")
    outside_path = tmp_path / "outside.png"
    outside_path.write_bytes(b"outside")
    missing_name = screenshot_name()
    collection = HistoryCollection(
        [
            {"screenshot": screenshot_url(owned_name)},
            {"screenshot": screenshot_url(missing_name)},
            {"screenshot": f"/screenshots/../{outside_path.name}"},
        ]
    )
    monkeypatch.setattr(main, "SCREENSHOT_DIRECTORY", screenshot_directory)
    monkeypatch.setattr(main, "scan_collection", collection)

    result = main.clear_history()

    assert result["status"] == "success"
    assert result["screenshot_cleanup"] == {
        "deleted": 1,
        "missing": 1,
        "failed": 0,
        "rejected": 1,
    }
    assert collection.delete_calls == 1
    assert not owned_path.exists()
    assert outside_path.read_bytes() == b"outside"


def test_clear_history_keeps_success_status_when_screenshot_cleanup_fails(monkeypatch, tmp_path):
    name = screenshot_name()
    collection = HistoryCollection([{"screenshot": screenshot_url(name)}])
    monkeypatch.setattr(main, "SCREENSHOT_DIRECTORY", tmp_path)
    monkeypatch.setattr(main, "scan_collection", collection)
    monkeypatch.setattr(main, "_delete_owned_screenshot", lambda _reference: "failed")

    result = main.clear_history()

    assert result["status"] == "success"
    assert result["screenshot_cleanup"]["failed"] == 1
    assert collection.delete_calls == 1


def test_orphan_retention_removes_only_aged_unreferenced_owned_screenshots(monkeypatch, tmp_path):
    orphan_name = screenshot_name()
    referenced_name = screenshot_name()
    orphan_path = tmp_path / orphan_name
    referenced_path = tmp_path / referenced_name
    orphan_path.write_bytes(b"orphan")
    referenced_path.write_bytes(b"referenced")
    old = time.time() - (31 * 24 * 60 * 60)
    os.utime(orphan_path, (old, old))
    os.utime(referenced_path, (old, old))
    collection = HistoryCollection([{"screenshot": screenshot_url(referenced_name)}])
    monkeypatch.setattr(main, "SCREENSHOT_DIRECTORY", tmp_path)
    monkeypatch.setattr(main, "scan_collection", collection)
    monkeypatch.setenv(main.ORPHAN_SCREENSHOT_RETENTION_DAYS_ENV, "30")

    result = main._cleanup_expired_orphan_screenshots()

    assert result["deleted"] == 1
    assert not orphan_path.exists()
    assert referenced_path.exists()


def test_tracked_configuration_uses_environment_variables_without_embedded_production_credentials():
    backend_root = Path(__file__).resolve().parents[1]
    database_source = (backend_root / "database.py").read_text(encoding="utf-8")
    virustotal_source = (backend_root / "threat_intel" / "virustotal.py").read_text(encoding="utf-8")

    assert 'os.environ.get("MONGO_URI"' in database_source
    assert "mongodb+srv://" not in database_source
    assert "os.environ.get(API_KEY_ENV" in virustotal_source
    assert 'API_KEY = "' not in virustotal_source
