from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware

import base64
import binascii
import logging
import os
import secrets
import time
import uuid
from pathlib import Path
from urllib.parse import unquote, urlsplit

from analyzer.risk_engine import analyze_url
from threat_intel.virustotal import check_url_virustotal
from detectors.phishing_detector import detect_phishing
from database import scan_collection
from security.url_validator import URLValidationError, validate_public_url
from services.sandbox_runner import SandboxExecutionError, run_sandbox


LOGGER = logging.getLogger(__name__)
SCREENSHOT_DIRECTORY = Path("screenshots")
SCREENSHOT_ROUTE_PREFIX = "/screenshots/"
API_TOKEN_ENV = "QRSHIELD_API_TOKEN"
ORPHAN_SCREENSHOT_RETENTION_DAYS_ENV = "QRSHIELD_SCREENSHOT_RETENTION_DAYS"
DEFAULT_ORPHAN_SCREENSHOT_RETENTION_DAYS = 30
FIXTURE_DIRECTORY = Path(__file__).resolve().parent / "evaluation" / "html" / "fixtures"
CONTROLLED_TEST_PLACEHOLDER = (
    Path(__file__).resolve().parents[1]
    / "Frontend"
    / "qrshield_app"
    / "assets"
    / "images"
    / "Logo.png"
)
MAX_SANDBOX_SCREENSHOT_BYTES = 20 * 1024 * 1024
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
# H3B2 development-only calibration selected 10 as the screening boundary.
# The high-risk boundary remains unchanged at 70.
SCREENING_THRESHOLD = 10
HIGH_RISK_THRESHOLD = 70

# TEST/DEVELOPMENT ONLY. This is intentionally a closed mapping rather than a
# request-controlled filename or HTML payload. It must not be used as phishing
# accuracy evidence or exposed by a production deployment.
CONTROLLED_UI_TEST_ENV = "QRSHIELD_ENABLE_CONTROLLED_UI_TEST"
CONTROLLED_UI_TEST_FIXTURE_ID = "fake_banking_login"
CONTROLLED_UI_TEST_FIXTURE_FILE = "fake_banking_login.html"
CONTROLLED_UI_TEST_URL = "https://secure-bank-login.example/verify-account"


class ScreenshotProcessingError(ValueError):
    """Raised when a worker screenshot cannot safely be persisted."""


def _risk_verdict(score: int) -> str:
    if score >= HIGH_RISK_THRESHOLD:
        return "High Risk"
    if score >= SCREENING_THRESHOLD:
        return "Medium Risk"
    return "Low Risk"


def _decode_sandbox_screenshot(screenshot_base64: str) -> bytes:
    max_base64_length = ((MAX_SANDBOX_SCREENSHOT_BYTES + 2) // 3) * 4
    if len(screenshot_base64) > max_base64_length:
        raise ScreenshotProcessingError("Sandbox screenshot is too large.")

    try:
        screenshot_bytes = base64.b64decode(screenshot_base64, validate=True)
    except (binascii.Error, TypeError, ValueError) as exc:
        raise ScreenshotProcessingError("Sandbox screenshot is invalid.") from exc

    if not screenshot_bytes or len(screenshot_bytes) > MAX_SANDBOX_SCREENSHOT_BYTES:
        raise ScreenshotProcessingError("Sandbox screenshot is too large.")

    if not screenshot_bytes.startswith(PNG_SIGNATURE):
        raise ScreenshotProcessingError("Sandbox screenshot is not a PNG image.")

    return screenshot_bytes


def _configured_api_token() -> str | None:
    token = os.environ.get(API_TOKEN_ENV, "").strip()
    return token or None


def require_sensitive_route_token(
    x_qrshield_api_token: str | None = Header(default=None, alias="X-QRShield-Api-Token"),
) -> None:
    """Protect stored data and scan submission with an operator-configured token."""
    configured_token = _configured_api_token()
    if configured_token is None:
        raise HTTPException(
            status_code=503,
            detail="Sensitive QRShield routes are unavailable until QRSHIELD_API_TOKEN is configured.",
        )
    if x_qrshield_api_token is None or not secrets.compare_digest(
        x_qrshield_api_token, configured_token
    ):
        raise HTTPException(status_code=401, detail="Unauthorized")


def _screenshot_path_for_name(screenshot_name: str) -> Path | None:
    """Return a generated screenshot path only when it is inside the screenshot root."""
    if not screenshot_name.endswith(".png"):
        return None
    try:
        parsed_uuid = uuid.UUID(screenshot_name[:-4])
    except (ValueError, AttributeError):
        return None
    if str(parsed_uuid) != screenshot_name[:-4].lower():
        return None

    screenshot_root = SCREENSHOT_DIRECTORY.resolve()
    candidate = (screenshot_root / screenshot_name).resolve()
    return candidate if candidate.parent == screenshot_root else None


def _screenshot_path_from_reference(screenshot_reference: object) -> Path | None:
    """Resolve only QRShield-owned screenshot URLs; never trust record paths directly."""
    if not isinstance(screenshot_reference, str):
        return None
    parsed = urlsplit(screenshot_reference)
    path = unquote(parsed.path)
    screenshot_name = Path(path).name
    if path != f"{SCREENSHOT_ROUTE_PREFIX}{screenshot_name}":
        return None
    return _screenshot_path_for_name(screenshot_name)


def _delete_owned_screenshot(screenshot_reference: object) -> str:
    """Delete an owned screenshot without permitting database path traversal."""
    screenshot_path = _screenshot_path_from_reference(screenshot_reference)
    if screenshot_path is None:
        return "rejected"
    try:
        screenshot_path.unlink()
    except FileNotFoundError:
        return "missing"
    except OSError as exc:
        LOGGER.warning("Could not remove history screenshot: %s", type(exc).__name__)
        return "failed"
    return "deleted"


def _orphan_screenshot_retention_days() -> int:
    raw_value = os.environ.get(ORPHAN_SCREENSHOT_RETENTION_DAYS_ENV, "").strip()
    if not raw_value:
        return DEFAULT_ORPHAN_SCREENSHOT_RETENTION_DAYS
    try:
        value = int(raw_value)
    except ValueError:
        LOGGER.warning("Invalid screenshot retention configuration; using default")
        return DEFAULT_ORPHAN_SCREENSHOT_RETENTION_DAYS
    if value < 1:
        LOGGER.warning("Screenshot retention configuration must be positive; using default")
        return DEFAULT_ORPHAN_SCREENSHOT_RETENTION_DAYS
    return value


def _cleanup_expired_orphan_screenshots() -> dict[str, int]:
    """Remove only aged UUID screenshots not referenced by current history records."""
    result = {"deleted": 0, "missing": 0, "failed": 0, "rejected": 0}
    if scan_collection is None:
        return result
    try:
        records = list(scan_collection.find({}, {"_id": 0, "screenshot": 1}))
    except Exception as exc:
        LOGGER.warning("Could not inspect screenshots for retention cleanup: %s", type(exc).__name__)
        return result

    referenced = {
        path
        for record in records
        if isinstance(record, dict)
        for path in [_screenshot_path_from_reference(record.get("screenshot"))]
        if path is not None
    }
    cutoff = time.time() - (_orphan_screenshot_retention_days() * 24 * 60 * 60)
    try:
        candidates = list(SCREENSHOT_DIRECTORY.glob("*.png"))
    except OSError as exc:
        LOGGER.warning("Could not enumerate screenshots for retention cleanup: %s", type(exc).__name__)
        return result

    for candidate in candidates:
        safe_candidate = _screenshot_path_for_name(candidate.name)
        if safe_candidate is None:
            result["rejected"] += 1
            continue
        try:
            if safe_candidate in referenced or safe_candidate.stat().st_mtime >= cutoff:
                continue
        except FileNotFoundError:
            result["missing"] += 1
            continue
        deletion = _delete_owned_screenshot(f"{SCREENSHOT_ROUTE_PREFIX}{safe_candidate.name}")
        result[deletion] += 1
    return result


def _require_history_collection():
    if scan_collection is None:
        raise HTTPException(status_code=503, detail="Scan history is not configured.")
    return scan_collection

app = FastAPI()

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLRequest(BaseModel):
    url: str


class ControlledScanRequest(BaseModel):
    fixture: str


def _controlled_ui_test_enabled() -> bool:
    """Return whether the explicitly opt-in inert UI harness is available."""
    return os.environ.get(CONTROLLED_UI_TEST_ENV) == "1"


def _require_controlled_ui_test_enabled() -> None:
    if not _controlled_ui_test_enabled():
        raise HTTPException(status_code=404, detail="Not found")


def _load_controlled_fixture(fixture_name: str) -> str:
    """Load the one inert allowlisted fixture without accepting a path."""
    if fixture_name != CONTROLLED_UI_TEST_FIXTURE_ID:
        raise HTTPException(status_code=400, detail="Unknown controlled test fixture.")

    fixture_root = FIXTURE_DIRECTORY.resolve()
    fixture_path = (fixture_root / CONTROLLED_UI_TEST_FIXTURE_FILE).resolve()
    if fixture_path.parent != fixture_root or not fixture_path.is_file():
        LOGGER.error("Controlled UI fixture configuration is invalid: %s", fixture_name)
        raise HTTPException(status_code=500, detail="Controlled test fixture is unavailable.")

    return fixture_path.read_text(encoding="utf-8")


# Home Route
@app.get("/")
def home():
    return {
        "message": "QRShield Sandbox Running"
    }


# TEST/DEVELOPMENT ONLY -- NOT A PHISHING ACCURACY BENCHMARK.
# This endpoint analyzes only an inert, local allowlisted fixture. It does not
# validate or visit a URL, run Playwright/the Docker sandbox, query VirusTotal,
# persist a screenshot, or write to MongoDB.
@app.post("/test/controlled-scan", include_in_schema=False)
def controlled_scan(data: ControlledScanRequest):
    _require_controlled_ui_test_enabled()

    html = _load_controlled_fixture(data.fixture)
    phishing_result = detect_phishing(html, page_url=CONTROLLED_UI_TEST_URL)
    risk_result = analyze_url(CONTROLLED_UI_TEST_URL, CONTROLLED_UI_TEST_URL)

    risk_score = risk_result["score"] + phishing_result["score"]
    reasons = [*risk_result["reasons"], *phishing_result["reasons"]]

    return {
        "status": "success",
        "original_url": CONTROLLED_UI_TEST_URL,
        "final_url": CONTROLLED_UI_TEST_URL,
        "title": f"TEST ONLY — inert fixture: {data.fixture}",
        "screenshot": "/test/static/controlled-placeholder.png",
        "risk_score": risk_score,
        "verdict": _risk_verdict(risk_score),
        "reasons": reasons,
        "virustotal": {
            "status": "test",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "verdict": "NOT_QUERIED",
        },
    }


@app.get("/test/static/controlled-placeholder.png", include_in_schema=False)
def controlled_test_placeholder():
    """Serve the existing local app logo only for the inert test response."""
    _require_controlled_ui_test_enabled()
    if not CONTROLLED_TEST_PLACEHOLDER.is_file():
        raise HTTPException(status_code=500, detail="Controlled test placeholder is unavailable.")
    return FileResponse(
        CONTROLLED_TEST_PLACEHOLDER,
        media_type="image/png",
        headers={"Cache-Control": "no-store"},
    )


@app.get("/screenshots/{screenshot_name}")
def get_screenshot(
    screenshot_name: str,
    _authorized: None = Depends(require_sensitive_route_token),
):
    screenshot_path = _screenshot_path_for_name(screenshot_name)
    if screenshot_path is None or not screenshot_path.is_file():
        raise HTTPException(status_code=404, detail="Screenshot not found")
    return FileResponse(
        screenshot_path,
        media_type="image/png",
        headers={"Cache-Control": "no-store"},
    )


# Scan Route
@app.post("/scan")
def scan_url(
    data: URLRequest,
    _authorized: None = Depends(require_sensitive_route_token),
):

    screenshot_name = f"{uuid.uuid4()}.png"
    screenshot_path = SCREENSHOT_DIRECTORY / screenshot_name
    screenshot_write_attempted = False
    scan_stored = False

    try:
        if scan_collection is None:
            LOGGER.warning("Scan history storage is not configured")
            return {
                "status": "error",
                "message": "Scan history storage is not configured."
            }
        url = validate_public_url(data.url)
        _cleanup_expired_orphan_screenshots()
        sandbox_result = run_sandbox(url)

        # Redirect validation is defense in depth only. It cannot stop DNS
        # rebinding or unsafe browser subresource egress; those require later
        # browser-time egress controls.
        final_url = validate_public_url(sandbox_result["final_url"])
        title = sandbox_result["title"]
        html = sandbox_result["html"]

        phishing_result = detect_phishing(html, page_url=final_url)

        screenshot_bytes = _decode_sandbox_screenshot(
            sandbox_result["screenshot_base64"]
        )
        try:
            screenshot_write_attempted = True
            screenshot_path.write_bytes(screenshot_bytes)
        except OSError as exc:
            LOGGER.warning("Could not persist sandbox screenshot: %s", type(exc).__name__)
            return {
                "status": "error",
                "message": "Sandbox screenshot could not be saved."
            }

        risk_score = phishing_result["score"]
        reasons = phishing_result["reasons"]

        risk_result = analyze_url(
            url,
            final_url
        )

        risk_result["score"] += risk_score

        risk_result["reasons"].extend(
            reasons
        )

        risk_result["verdict"] = _risk_verdict(risk_result["score"])

        vt_result = check_url_virustotal(
            final_url
        )

        screenshot_url = (
            f"http://localhost:8000/screenshots/{screenshot_name}"
        )

        scan_collection.insert_one({
            "original_url": url,
            "final_url": final_url,
            "title": title,
            "screenshot": screenshot_url,
            "risk_score": risk_result["score"],
            "verdict": risk_result["verdict"],
            "reasons": risk_result["reasons"],
            "virustotal": vt_result
        })
        scan_stored = True

        return {
            "status": "success",
            "original_url": url,
            "final_url": final_url,
            "title": title,
            "screenshot": screenshot_url,
            "risk_score": risk_result["score"],
            "verdict": risk_result["verdict"],
            "reasons": risk_result["reasons"],
            "virustotal": vt_result
        }

    except URLValidationError as exc:
        LOGGER.warning("Scan URL validation failed: %s", type(exc).__name__)
        return {
            "status": "error",
            "message": "URL is not allowed for analysis."
        }

    except SandboxExecutionError as exc:
        LOGGER.warning("Sandbox analysis failed: %s", exc)
        return {
            "status": "error",
            "message": "Sandbox analysis could not be completed."
        }

    except ScreenshotProcessingError as exc:
        LOGGER.warning("Sandbox screenshot validation failed: %s", exc)
        return {
            "status": "error",
            "message": "Sandbox screenshot could not be processed."
        }

    except Exception:
        LOGGER.exception("Scan analysis failed")

        return {
            "status": "error",
            "message": "Scan analysis could not be completed."
        }

    finally:
        if screenshot_write_attempted and not scan_stored:
            try:
                screenshot_path.unlink(missing_ok=True)
            except OSError as exc:
                LOGGER.warning("Could not remove failed scan screenshot: %s", type(exc).__name__)


# History API
@app.get("/history")
def get_scan_history(_authorized: None = Depends(require_sensitive_route_token)):

    scans = list(
        _require_history_collection().find(
            {},
            {"_id": 0}
        ).sort("_id", -1)
    )

    return scans


# Clear History API
@app.delete("/history")
def clear_history(_authorized: None = Depends(require_sensitive_route_token)):
    collection = _require_history_collection()
    try:
        records = list(collection.find({}, {"_id": 0, "screenshot": 1}))
        collection.delete_many({})
    except Exception as exc:
        LOGGER.warning("Could not clear scan history: %s", type(exc).__name__)
        raise HTTPException(status_code=500, detail="Scan history could not be cleared.") from exc

    screenshot_cleanup = {"deleted": 0, "missing": 0, "failed": 0, "rejected": 0}
    for record in records:
        screenshot_reference = record.get("screenshot") if isinstance(record, dict) else None
        outcome = _delete_owned_screenshot(screenshot_reference)
        screenshot_cleanup[outcome] += 1

    orphan_cleanup = _cleanup_expired_orphan_screenshots()
    return {
        "status": "success",
        "message": "History cleared",
        "screenshot_cleanup": screenshot_cleanup,
        "orphan_screenshot_cleanup": orphan_cleanup,
    }


# Stats API
@app.get("/stats")
def get_stats(_authorized: None = Depends(require_sensitive_route_token)):

    scans = list(
        _require_history_collection().find(
            {},
            {"_id": 0}
        )
    )

    total_scans = len(scans)

    low_risk = 0
    medium_risk = 0
    high_risk = 0

    for scan in scans:

        verdict = scan.get(
            "verdict",
            ""
        )

        if verdict == "Low Risk":
            low_risk += 1

        elif verdict == "Medium Risk":
            medium_risk += 1

        elif verdict == "High Risk":
            high_risk += 1

    return {
        "status": "success",
        "total_scans": total_scans,
        "low_risk": low_risk,
        "medium_risk": medium_risk,
        "high_risk": high_risk
    }
