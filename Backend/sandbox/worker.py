"""Single-use Playwright worker for an isolated QRShield scan.

The worker reads one JSON object from stdin and writes one JSON object to
stdout.  Stdout is intentionally reserved for this machine-readable result;
diagnostic information is written to stderr only.
"""

import base64
import json
import os
import sys
from typing import Any
from urllib.parse import urlsplit

from network_guard import validate_request_destination


NAVIGATION_TIMEOUT_MS = 60_000
DEVELOPMENT_DIRECT_MODE_ENV = "QRSHIELD_ALLOW_DIRECT_MODE"


class ProxyConfigurationError(ValueError):
    """Raised when the controlled egress-proxy setting is unsafe or absent."""


def _error(message: str) -> dict[str, str]:
    return {"status": "error", "message": message}


def _debug(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def _emit(result: dict[str, Any]) -> None:
    """Write the worker's sole machine-readable result."""
    sys.stdout.write(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
    sys.stdout.write("\n")
    sys.stdout.flush()


def _read_url() -> tuple[str | None, dict[str, str] | None]:
    """Read and perform Stage A validation for one stdin JSON object."""
    try:
        payload = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, OSError, UnicodeError):
        return None, _error("Input must be a valid JSON object.")

    if not isinstance(payload, dict):
        return None, _error("Input must be a JSON object.")

    value = payload.get("url")
    if not isinstance(value, str) or not value.strip():
        return None, _error("Input must include a non-empty 'url' string.")

    url = value.strip()
    try:
        parsed = urlsplit(url)
    except ValueError:
        return None, _error("URL is malformed.")
    if parsed.scheme.lower() not in {"http", "https"}:
        return None, _error("Only http and https URLs are supported.")

    if not parsed.netloc or not parsed.hostname:
        return None, _error("URL must include a hostname.")

    return url, None


def get_egress_proxy() -> str | None:
    """Return the required controlled proxy or an explicit development opt-in.

    Production workers require ``QRSHIELD_EGRESS_PROXY`` and must never infer
    direct mode from a missing value. ``QRSHIELD_ALLOW_DIRECT_MODE=1`` exists
    only for isolated development tests; the production sandbox runner never
    sets it.
    """
    value = os.environ.get("QRSHIELD_EGRESS_PROXY")
    if value is None:
        if os.environ.get(DEVELOPMENT_DIRECT_MODE_ENV) == "1":
            return None
        raise ProxyConfigurationError("Controlled egress proxy is required.")
    if not value.strip():
        raise ProxyConfigurationError("Egress proxy URL is empty.")

    proxy_server = value.strip()
    try:
        parsed = urlsplit(proxy_server)
        port = parsed.port
    except ValueError as exc:
        raise ProxyConfigurationError("Egress proxy URL is malformed.") from exc

    if parsed.scheme.lower() != "http":
        raise ProxyConfigurationError("Egress proxy must use the http scheme.")
    if not parsed.netloc or not parsed.hostname:
        raise ProxyConfigurationError("Egress proxy must include a hostname.")
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        raise ProxyConfigurationError("Egress proxy credentials are not allowed.")
    if port is None or not 1 <= port <= 65535:
        raise ProxyConfigurationError("Egress proxy must include a valid port.")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ProxyConfigurationError("Egress proxy URL must not include a path or query.")

    return proxy_server.rstrip("/")


def _close_safely(resource: Any, label: str) -> None:
    if resource is None:
        return

    try:
        resource.close()
    except Exception as exc:  # Cleanup must never replace the scan result.
        _debug(f"Cleanup warning while closing {label}: {type(exc).__name__}")


def _abort_request(route: Any) -> None:
    try:
        route.abort("blockedbyclient")
    except Exception as exc:
        _debug(f"Network abort warning: {type(exc).__name__}")


def _guard_route(route: Any, *, proxy_mode: bool = False) -> None:
    """Continue only browser-internal or publicly routable HTTP(S) requests."""
    try:
        validate_request_destination(
            route.request.url,
            resolve_hostname_dns=not proxy_mode,
        )
    except Exception as exc:
        # Do not include the URL because queries can contain credentials.
        _debug(f"Network request blocked: {type(exc).__name__}")
        _abort_request(route)
        return

    try:
        route.continue_()
    except Exception as exc:
        _debug(f"Network continuation warning: {type(exc).__name__}")
        _abort_request(route)


def _block_web_socket(web_socket_route: Any) -> None:
    """Close all routed WebSockets before they can provide an egress path."""
    try:
        web_socket_route.close(code=1008, reason="Blocked by QRShield")
    except Exception as exc:
        _debug(f"WebSocket block warning: {type(exc).__name__}")


def _chromium_launch_options(proxy_server: str | None) -> dict[str, Any]:
    """Create official Playwright launch options without proxy bypasses."""
    options: dict[str, Any] = {"headless": True}
    if proxy_server is not None:
        options["proxy"] = {"server": proxy_server}
    return options


def _launch_browser(chromium: Any, proxy_server: str | None) -> Any:
    return chromium.launch(**_chromium_launch_options(proxy_server))


def _analyze_url(url: str, *, proxy_server: str | None = None) -> dict[str, str]:
    """Render one URL and return only collection data for the backend."""
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
        from playwright.sync_api import sync_playwright
    except Exception as exc:
        _debug(f"Playwright import failed: {type(exc).__name__}")
        return _error("Browser automation runtime is unavailable.")

    page = None
    context = None
    browser = None
    stage = "browser launch"

    try:
        with sync_playwright() as playwright:
            try:
                browser = _launch_browser(playwright.chromium, proxy_server)
                context = browser.new_context(
                    accept_downloads=False,
                    service_workers="block",
                )
                context.route(
                    "**/*",
                    lambda route: _guard_route(route, proxy_mode=proxy_server is not None),
                )
                context.route_web_socket("**/*", _block_web_socket)
                page = context.new_page()

                def close_popup(popup: Any) -> None:
                    try:
                        popup.close(run_before_unload=False)
                    except Exception as exc:
                        _debug(f"Popup cleanup warning: {type(exc).__name__}")

                # Pages created after the primary page are unsolicited popups/new tabs.
                context.on("page", close_popup)

                stage = "navigation"
                page.goto(
                    url,
                    timeout=NAVIGATION_TIMEOUT_MS,
                    wait_until="load",
                )

                stage = "page information collection"
                final_url = page.url
                title = page.title()
                html = page.content()

                stage = "screenshot capture"
                screenshot_bytes = page.screenshot(type="png", full_page=True)
                screenshot_base64 = base64.b64encode(screenshot_bytes).decode("ascii")

                return {
                    "status": "success",
                    "final_url": final_url,
                    "title": title,
                    "html": html,
                    "screenshot_base64": screenshot_base64,
                }
            finally:
                _close_safely(page, "page")
                _close_safely(context, "browser context")
                _close_safely(browser, "browser")
    except PlaywrightTimeoutError as exc:
        _debug(f"Playwright timeout during {stage}: {type(exc).__name__}")
        return _error(f"Browser analysis timed out during {stage}.")
    except PlaywrightError as exc:
        _debug(f"Playwright failure during {stage}: {type(exc).__name__}")
        messages = {
            "browser launch": "Chromium could not start.",
            "navigation": "The destination could not be loaded.",
            "page information collection": "Page information could not be collected.",
            "screenshot capture": "A screenshot could not be captured.",
        }
        return _error(messages.get(stage, "Browser analysis failed."))
    except Exception as exc:
        _debug(f"Unexpected worker failure during {stage}: {type(exc).__name__}")
        return _error("Sandbox worker failed while analyzing the URL.")


def main() -> None:
    url, input_error = _read_url()
    if input_error is not None:
        _emit(input_error)
        return

    try:
        proxy_server = get_egress_proxy()
    except ProxyConfigurationError as exc:
        _debug(f"Proxy configuration rejected: {type(exc).__name__}")
        _emit(_error("Egress proxy configuration is invalid."))
        return

    _emit(_analyze_url(url, proxy_server=proxy_server))


if __name__ == "__main__":
    main()
