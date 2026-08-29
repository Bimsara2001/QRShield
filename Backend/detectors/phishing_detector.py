from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin, urlsplit


_EVAL_CALL_PATTERN = re.compile(r"\beval\s*\(")
_EXECUTABLE_SCRIPT_TYPES = {
    "",
    "text/javascript",
    "application/javascript",
    "text/ecmascript",
    "application/ecmascript",
    "module",
}
_CREDENTIAL_CONTEXT_PHRASES = (
    "verify your account",
    "verify account",
    "confirm your identity",
    "confirm identity",
    "re-enter your password",
    "confirm your password",
    "unlock your account",
    "account suspended",
    "account has been suspended",
    "session expired",
    "sign in to continue",
    "login to continue",
)


def _normalized_hostname(url):
    try:
        hostname = urlsplit(url).hostname
    except ValueError:
        return None
    if not hostname:
        return None
    return hostname.rstrip(".").lower()


def _has_external_credential_action(form, page_url, password_inputs):
    if not password_inputs or not page_url:
        return False

    action = (form.get("action") or "").strip()
    if not action or action == "#":
        return False

    try:
        resolved = urljoin(page_url, action)
        parsed = urlsplit(resolved)
    except ValueError:
        return False

    if parsed.scheme.lower() not in {"http", "https"}:
        return False

    page_host = _normalized_hostname(page_url)
    action_host = _normalized_hostname(resolved)
    return bool(page_host and action_host and page_host != action_host)


def _has_eval_call(soup):
    for script in soup.find_all("script"):
        script_type = (script.get("type") or "").split(";", 1)[0].strip().lower()
        if script_type not in _EXECUTABLE_SCRIPT_TYPES:
            continue
        if _EVAL_CALL_PATTERN.search(script.get_text()):
            return True
    return False


def _normalise_context_text(value):
    return " ".join(value.lower().split())


def _has_credential_context(form):
    password_inputs = form.find_all("input", {"type": "password"})
    if not password_inputs:
        return False

    form_text = _normalise_context_text(form.get_text(" ", strip=True))
    return any(
        _normalise_context_text(phrase) in form_text
        for phrase in _CREDENTIAL_CONTEXT_PHRASES
    )


def detect_phishing(html, page_url=None):

    score = 0

    reasons = []

    soup = BeautifulSoup(html, "html.parser")

    password_inputs = soup.find_all(
        "input",
        {"type": "password"}
    )

    suspicious_keywords = [
    "verify your account",
    "bank login",
    "credit card",
    "password reset",
    "confirm identity",
    "security alert",
    "urgent action required",
    "claim reward",
    "free money",
    "limited time offer"
]

    html_lower = html.lower()

    for keyword in suspicious_keywords:

        if keyword.lower() in html_lower:

            score += 5

            reasons.append(
                f"Suspicious keyword detected: {keyword}"
            )

    if password_inputs:

        score += 20

        reasons.append(
            "Password input field detected"
        )

    if any(
        _has_external_credential_action(form, page_url, form.find_all("input", {"type": "password"}))
        for form in soup.find_all("form")
    ):
        score += 10
        reasons.append(
            "Credential form submits to an external destination"
        )

    if any(_has_credential_context(form) for form in soup.find_all("form")):
        score += 10
        reasons.append(
            "Credential verification language detected"
        )

    if soup.find("iframe") is not None:

        score += 10

        reasons.append(
            "iframe detected"
        )

    if _has_eval_call(soup):

        score += 15

        reasons.append(
            "Potentially dangerous JavaScript detected"
        )

    return {
        "score": score,
        "reasons": reasons
    }
