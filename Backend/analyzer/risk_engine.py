import re
import tldextract
from urllib.parse import urlsplit

SUSPICIOUS_KEYWORDS = {
    "login": 15,
    "verify": 15,
    "secure": 15,
    "update": 10,
    "bank": 15,
    "account": 10,
    "password": 20,
    "wallet": 15,
    "crypto": 10,
    "free": 10,
    "bonus": 10,
    "gift": 15,
    "paypal": 20,
    "security": 15,
    "check": 10,
    "signin": 15,
    "confirm": 15,
}

SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "ow.ly",
    "is.gd",
]


def _shortener_hostname_matches(url, shortener):
    """Return whether the parsed hostname is the configured shortener host."""
    try:
        hostname = urlsplit(url).hostname
    except ValueError:
        return False
    if not hostname:
        return False

    hostname = hostname.lower()
    if hostname.endswith("."):
        hostname = hostname[:-1]
    shortener = shortener.lower()
    if shortener.endswith("."):
        shortener = shortener[:-1]

    return hostname == shortener or hostname.endswith("." + shortener)


def _normalize_url_for_redirect_comparison(url):
    """Normalize only URL serialization differences that preserve destination."""
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        # Preserve the old conservative behavior for malformed URLs.
        return ("raw", url)

    hostname = parsed.hostname
    if hostname:
        hostname = hostname.lower()
        if hostname.endswith("."):
            hostname = hostname[:-1]
        # Treat only the conventional web-host prefix as canonical for
        # redirect-risk comparison. Other subdomains remain significant.
        if hostname.startswith("www.") and hostname != "www.":
            hostname = hostname[4:]

    if (parsed.scheme.lower() == "http" and port == 80) or (
        parsed.scheme.lower() == "https" and port == 443
    ):
        port = None

    # Query strings remain significant. Fragments are client-side state and
    # are intentionally ignored because they are not sent to the server.
    return (
        parsed.scheme.lower(),
        parsed.username,
        parsed.password,
        hostname,
        port,
        parsed.path or "/",
        parsed.query,
    )


def analyze_url(url, final_url):

    score = 0
    reasons = []

    url_lower = url.lower()

    # HTTPS Check
    if not url.startswith("https://"):
        score += 15
        reasons.append("URL does not use HTTPS")

    # URL Length Check
    if len(url) > 75:
        score += 10
        reasons.append("Very long URL")

    # Suspicious Keywords
    for keyword, weight in SUSPICIOUS_KEYWORDS.items():
        if keyword in url_lower:
            score += weight
            reasons.append(
                f"Suspicious keyword detected: {keyword}"
            )

    # Too Many Dots
    if url.count(".") > 4:
        score += 10
        reasons.append("Too many dots in URL")

    # Shortener Detection
    for shortener in SHORTENERS:
        if _shortener_hostname_matches(url, shortener):
            score += 40
            reasons.append("URL shortener detected")

    # IP Address Detection
    ip_pattern = r"(?:\d{1,3}\.){3}\d{1,3}"

    if re.search(ip_pattern, url):
        score += 25
        reasons.append("IP address used instead of domain")

    # Hyphen Detection
    if "-" in url:
        score += 10
        reasons.append("Hyphenated URL detected")

    if url.count("-") >= 2:
        score += 15
        reasons.append("Multiple hyphens detected")

    # Redirect Detection
    if _normalize_url_for_redirect_comparison(url) != _normalize_url_for_redirect_comparison(final_url):
        score += 10
        reasons.append("URL redirected to another address")

    # Domain Analysis
    extracted = tldextract.extract(url)

    domain = extracted.domain

    if len(domain) > 20:
        score += 10
        reasons.append("Suspiciously long domain name")

    # Classification
    if score <= 30:
        verdict = "SAFE"

    elif score <= 60:
        verdict = "SUSPICIOUS"

    else:
        verdict = "DANGEROUS"

    return {
        "score": score,
        "verdict": verdict,
        "reasons": reasons
    }
