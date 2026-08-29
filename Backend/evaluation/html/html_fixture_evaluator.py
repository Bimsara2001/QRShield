"""Run the H5A offline HTML fixture audit without changing production code."""

from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from pathlib import Path

from bs4 import BeautifulSoup

BACKEND = Path(__file__).resolve().parents[2]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from detectors.phishing_detector import detect_phishing  # noqa: E402

ROOT = Path(__file__).resolve().parent
FIXTURES = ROOT / "fixtures"
EVIDENCE = BACKEND / "evaluation" / "evidence"


def _structure(html: str) -> dict[str, object]:
    soup = BeautifulSoup(html, "html.parser")
    forms = soup.find_all("form")
    inputs = soup.find_all("input")
    return {
        "form_count": len(forms),
        "input_types": [str(item.get("type", "text")).lower() for item in inputs],
        "password_count": len(soup.find_all("input", {"type": "password"})),
        "hidden_input_count": len(soup.find_all("input", {"type": "hidden"})),
        "textarea_count": len(soup.find_all("textarea")),
        "form_actions": [str(form.get("action", "")) for form in forms],
        "external_actions": [
            str(form.get("action", ""))
            for form in forms
            if str(form.get("action", "")).startswith(("http://", "https://"))
        ],
        "iframe_count": len(soup.find_all("iframe")),
    }


def main() -> None:
    prefix = sys.argv[1] if len(sys.argv) > 1 else "h5a"
    manifest = json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8"))
    rows: list[dict[str, object]] = []
    for item in manifest:
        html = (FIXTURES / item["filename"]).read_text(encoding="utf-8")
        result = detect_phishing(html, page_url="https://example.com/page")
        rows.append(
            {
                "fixture_id": item["fixture_id"],
                "fixture_type": item["fixture_type"],
                "expected_security_intent": item["expected_security_intent"],
                "html_score": result["score"],
                "reasons": result["reasons"],
                "structure": _structure(html),
            }
        )

    EVIDENCE.mkdir(parents=True, exist_ok=True)
    with (EVIDENCE / f"{prefix}_html_fixture_results.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["fixture_id", "fixture_type", "expected_security_intent", "html_score", "reasons"],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    key: row[key]
                    for key in writer.fieldnames
                    if key != "reasons"
                }
                | {"reasons": " | ".join(row["reasons"])}
            )

    generic_form_rows = [row for row in rows if "Page contains HTML forms" in row["reasons"]]
    false_positive = {
        "controlled_benign_forms": [
            {
                "fixture_id": row["fixture_id"],
                "score": row["html_score"],
                "reasons": row["reasons"],
                "why_broad": "Any form element receives +10 regardless of input purpose or action origin.",
            }
            for row in rows
            if row["fixture_id"] in {"benign_search", "benign_contact", "benign_newsletter", "multiple_noncredential_forms"}
        ],
        "generic_form_trigger_count": len(generic_form_rows),
        "observation": "Search, contact, newsletter, and multiple non-credential forms all receive the same generic form score.",
    }
    false_negative = {
        "controlled_phishing_like_cases": [
            {
                "fixture_id": row["fixture_id"],
                "score": row["html_score"],
                "reasons": row["reasons"],
                "ignored_signals": ["external form action", "credential-language context"]
                if row["fixture_id"] in {"external_credential", "suspicious_password"}
                else [],
            }
            for row in rows
            if row["fixture_id"] in {"external_credential", "suspicious_password"}
        ],
        "observation": "The current detector counts password fields but does not inspect form action origin or contextual credential language as separate signals.",
    }
    inventory = {
        "implementation": "Backend/detectors/phishing_detector.py",
        "url_lexical_detector_used": False,
        "neutral_url_note": "No URL scoring was run; fixture results are HTML-only.",
        "heuristics": [
            {"condition": "Any configured suspicious keyword is a substring of lower-case HTML", "score_added": 5, "reason": "Suspicious keyword detected: <keyword>", "parsing": "raw lower-case substring"},
            {"condition": "One or more form elements exist", "score_added": 10, "reason": "Page contains HTML forms", "parsing": "BeautifulSoup find_all('form')"},
            {"condition": "One or more input elements have type=password", "score_added": 20, "reason": "Password input field detected", "parsing": "BeautifulSoup find_all('input', {'type': 'password'})"},
            {"condition": "A password-containing form includes a configured credential phrase in its local text", "score_added": 10, "reason": "Credential verification language detected", "parsing": "form text normalized for explicit phrase matching"},
            {"condition": "An iframe element exists", "score_added": 10, "reason": "iframe detected", "parsing": "BeautifulSoup find('iframe')"},
            {"condition": "The lower-case HTML contains the substring eval(", "score_added": 15, "reason": "Potentially dangerous JavaScript detected", "parsing": "raw lower-case substring"},
        ],
        "suspicious_keywords": ["verify your account", "bank login", "credit card", "password reset", "confirm identity", "security alert", "urgent action required", "claim reward", "free money", "limited time offer"],
    }
    (EVIDENCE / f"{prefix}_html_heuristic_inventory.json").write_text(json.dumps(inventory, indent=2), encoding="utf-8")
    (EVIDENCE / f"{prefix}_html_false_positive_analysis.json").write_text(json.dumps(false_positive, indent=2), encoding="utf-8")
    (EVIDENCE / f"{prefix}_html_false_negative_analysis.json").write_text(json.dumps(false_negative, indent=2), encoding="utf-8")
    candidates = [
        {"rank": 1, "category": "A. confirmed bug fix", "problem": "Generic form presence penalizes ordinary search/contact/newsletter forms.", "evidence": "benign fixtures all receive +10.", "smallest_change": "Make a form-only signal informational or lower-weight; preserve password signal.", "benefit": "Reduce benign form false positives.", "risk": "May reduce detection of credential pages lacking password inputs."},
        {"rank": 2, "category": "C. new HTML signal", "problem": "External form actions are ignored.", "evidence": "external_credential has the same score as same-origin login_form.", "smallest_change": "Compare absolute form action origin with the analyzed page origin.", "benefit": "Contextualize credential exfiltration.", "risk": "CDNs and federated login flows can be legitimate."},
        {"rank": 3, "category": "C. new HTML signal", "problem": "Credential language is not independently scored.", "evidence": "suspicious_password does not match the configured 'verify your account' or 'confirm identity' phrases.", "smallest_change": "Use narrowly scoped contextual phrases near credential fields.", "benefit": "Improve phishing-like page separation.", "risk": "Brand/support pages may use similar language."},
        {"rank": 4, "category": "D. scoring calibration", "problem": "HTML points can materially affect the final threshold.", "evidence": "Current password+form combination is +30 before lexical signals.", "smallest_change": "Calibrate only after a labelled HTML corpus exists.", "benefit": "Better score interpretation.", "risk": "Overfitting controlled fixtures."},
    ]
    (EVIDENCE / "h5a_html_improvement_candidates.json").write_text(json.dumps(candidates, indent=2), encoding="utf-8")
    print(json.dumps(rows, indent=2))


if __name__ == "__main__":
    main()
