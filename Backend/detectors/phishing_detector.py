from bs4 import BeautifulSoup


def detect_phishing(html):

    score = 0

    reasons = []

    soup = BeautifulSoup(html, "html.parser")

    forms = soup.find_all("form")

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

    if forms:

        score += 10

        reasons.append(
            "Page contains HTML forms"
        )

    if password_inputs:

        score += 20

        reasons.append(
            "Password input field detected"
        )

    if "iframe" in html_lower:

        score += 10

        reasons.append(
            "iframe detected"
        )

    if "eval(" in html_lower:

        score += 15

        reasons.append(
            "Potentially dangerous JavaScript detected"
        )

    return {
        "score": score,
        "reasons": reasons
    }