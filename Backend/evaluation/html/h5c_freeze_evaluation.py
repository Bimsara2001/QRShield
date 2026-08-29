"""Reproducible H5C controlled validation of the frozen HTML detector."""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[2]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from detectors.phishing_detector import detect_phishing  # noqa: E402

ROOT = Path(__file__).resolve().parent
FIXTURES = ROOT / "fixtures"
EVIDENCE = BACKEND / "evaluation" / "evidence"

BENIGN = {
    "plain_benign", "benign_search", "benign_contact", "benign_newsletter",
    "multiple_noncredential_forms", "iframe_text_only", "iframe_comment_only",
    "iframe_script_only", "eval_text_only", "eval_comment_only", "eval_code_only",
    "eval_attribute_only", "eval_json_script", "credential_phrase_no_password",
}
SUSPICIOUS = {
    "login_form": ["Password input field detected"],
    "external_credential": ["Password input field detected", "Credential form submits to an external destination"],
    "password_plain": ["Password input field detected"],
    "password_verify_phrase": ["Password input field detected", "Credential verification language detected"],
    "password_confirm_phrase": ["Password input field detected", "Credential verification language detected"],
    "external_credential_phrase": ["Password input field detected", "Credential form submits to an external destination", "Credential verification language detected"],
    "hidden_iframe": ["iframe detected"],
    "eval_executable_script": ["Potentially dangerous JavaScript detected"],
    "eval_whitespace_script": ["Potentially dangerous JavaScript detected"],
    # The legacy fixture keeps its phrases outside the form; H5B5's bounded
    # context intentionally does not treat those distant phrases as local.
    "fake_banking_login": ["Password input field detected", "Credential form submits to an external destination"],
}


def main() -> None:
    manifest = json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8"))
    rows = []
    for item in manifest:
        fixture_id = item["fixture_id"]
        html = (FIXTURES / item["filename"]).read_text(encoding="utf-8")
        result = detect_phishing(html, page_url="https://example.com/page")
        reasons = result["reasons"]
        if fixture_id in BENIGN:
            intent, expected, passed = "BENIGN", "no new contextual HTML signal", not any(
                reason in reasons
                for reason in (
                    "Password input field detected",
                    "Credential form submits to an external destination",
                    "Credential verification language detected",
                    "iframe detected",
                    "Potentially dangerous JavaScript detected",
                )
            )
        elif fixture_id in SUSPICIOUS:
            intent, expected = "SUSPICIOUS_CONTROLLED", "all fixture-defined signals present"
            passed = all(reason in reasons for reason in SUSPICIOUS[fixture_id])
        else:
            intent, expected, passed = "ADDITIONAL_CONTROL", "no form-local credential context", "Credential verification language detected" not in reasons
        rows.append({
            "fixture_id": fixture_id,
            "fixture_type": item["fixture_type"],
            "intent": intent,
            "expected_outcome": expected,
            "observed_score": result["score"],
            "observed_reasons": " | ".join(reasons),
            "pass": passed,
        })

    EVIDENCE.mkdir(parents=True, exist_ok=True)
    with (EVIDENCE / "h5c_controlled_validation.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(json.dumps({
        "benign_count": sum(row["intent"] == "BENIGN" for row in rows),
        "suspicious_controlled_count": sum(row["intent"] == "SUSPICIOUS_CONTROLLED" for row in rows),
        "additional_control_count": sum(row["intent"] == "ADDITIONAL_CONTROL" for row in rows),
        "passed": sum(bool(row["pass"]) for row in rows),
        "failed": sum(not bool(row["pass"]) for row in rows),
        "rows": rows,
    }, indent=2))


if __name__ == "__main__":
    main()
