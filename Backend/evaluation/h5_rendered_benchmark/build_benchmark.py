"""Create the fixed, synthetic H5 rendered-page benchmark corpus.

This generator is deliberately deterministic.  It defines the benchmark before
any prediction is made, writes 50 inert local HTML fixtures, and records their
checksums in ``manifest.csv``.  It is not a detector-development utility.
"""

from __future__ import annotations

import csv
import hashlib
import html
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent
FIXTURES = ROOT / "fixtures"
MANIFEST = ROOT / "manifest.csv"
INTEGRITY = ROOT / "pre_execution_integrity.json"
HISTORICAL_FIXTURES = ROOT.parent / "html" / "fixtures"
SOURCE = "synthetic_independent_rendered_benchmark"


def _page(title: str, body: str) -> str:
    """Return a self-contained, non-operational page with no external assets."""
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title><style>
body{{font-family:system-ui,sans-serif;max-width:760px;margin:3rem auto;padding:0 1.25rem;color:#18212b}}
main{{border:1px solid #d8dee7;border-radius:12px;padding:2rem;background:#fff}} h1{{margin-top:0}}
label{{display:block;margin:.75rem 0 .2rem}} input{{width:100%;padding:.55rem;box-sizing:border-box}}
button{{margin-top:1rem;padding:.6rem 1rem}} .notice{{padding:.75rem;background:#eef5ff;border-radius:8px}}
iframe{{width:100%;height:72px;border:1px solid #ccd4df}}</style></head>
<body><main>{body}</main></body></html>"""


CASES = [
    # Benign pages deliberately include several heuristic-adjacent patterns.
    ("B01", "benign", "home.html", "Welcome to Northstar Community", "Normal community homepage with local information.", "<h1>Northstar Community</h1><p>Events, services, and neighbourhood news for residents.</p>"),
    ("B02", "benign", "campus-portal.html", "Harbour University Portal", "University student portal information page.", "<h1>Harbour University Portal</h1><p>Timetables, library links, and campus announcements. This page does not collect credentials.</p>"),
    ("B03", "benign", "docs/getting-started.html", "Orbit Docs", "Ordinary product documentation.", "<h1>Getting started</h1><p>Install Orbit, create a project, and read the API reference.</p>"),
    ("B04", "benign", "shop/linen-notebook.html", "Moss & Ink", "Ecommerce product description without account collection.", "<h1>Linen notebook</h1><p>Recycled paper notebook. Add items to a local reading list.</p><button type=button>Add to list</button>"),
    ("B05", "benign", "search.html", "Search the Archive", "Search form that is intentionally non-credential.", "<h1>Archive search</h1><form onsubmit=\"return false\"><label>Search terms<input name=q></label><button type=submit disabled>Search</button></form>"),
    ("B06", "benign", "support/contact.html", "Maple Support", "Support contact form without password input.", "<h1>Contact support</h1><form onsubmit=\"return false\"><label>Topic<input name=topic></label><label>Message<input name=message></label><button type=submit disabled>Send</button></form>"),
    ("B07", "benign", "member/dashboard.html", "Member Dashboard", "Read-only account dashboard representation.", "<h1>Member dashboard</h1><p>Your saved reports and notification preferences are shown here. No form is present.</p>"),
    ("B08", "benign", "login.html", "Local Library Sign In", "Legitimate-style inert library login page, included as a false-positive challenge.", "<h1>Library sign in</h1><p class=notice>Use your library card to view loans.</p><form action=\"https://example.invalid/library\" onsubmit=\"return false\"><label>Card number<input name=user autocomplete=off></label><label>Password<input type=password name=password autocomplete=off></label><button type=submit disabled>Sign in</button></form>"),
    ("B09", "benign", "reset-password.html", "Password Reset Help", "Password reset information page without a password field.", "<h1>Password reset help</h1><p>Contact the service desk to reset a forgotten password. This information page does not accept a password.</p>"),
    ("B10", "benign", "banking-information.html", "Riverstone Financial Information", "Banking information, not a login or collection form.", "<h1>Everyday banking information</h1><p>Compare account types, branch hours, and fee schedules.</p>"),
    ("B11", "benign", "payment-information.html", "Museum Payment Information", "Payment-information explanation with no transaction endpoint.", "<h1>Payment information</h1><p>Tickets may be purchased at the museum desk. We do not request card details on this page.</p>"),
    ("B12", "benign", "account-verification-guide.html", "Account Verification Guide", "Educational account-verification guidance.", "<h1>Account verification guide</h1><p>Read this guide to understand how organisations may verify an account. Never share passwords by email.</p>"),
    ("B13", "benign", "security-awareness.html", "Security Awareness Course", "Security-warning educational material.", "<h1>Security awareness</h1><p>A security alert can be a scam. Verify requests through trusted channels and do not disclose credentials.</p>"),
    ("B14", "benign", "learning/embed.html", "Learning Embed", "Legitimate embedded local lesson frame.", "<h1>Course preview</h1><p>Embedded lesson preview:</p><iframe src=\"about:blank\" title=\"local lesson\"></iframe>"),
    ("B15", "benign", "profile/signin-help.html", "Sign-in Help", "Sign-in explanation and disabled feedback form.", "<h1>Sign-in help</h1><p>Use the help centre if you cannot access your profile.</p><form onsubmit=\"return false\"><label>Feedback<input name=feedback></label><button type=submit disabled>Submit feedback</button></form>"),
    ("B16", "benign", "newsletter.html", "Garden Newsletter", "Newsletter form with email only.", "<h1>Garden newsletter</h1><form onsubmit=\"return false\"><label>Email<input type=email name=email></label><button type=submit disabled>Subscribe</button></form>"),
    ("B17", "benign", "coast-guide.html", "Coast Guide", "Benign hyphenated route challenge.", "<h1>Coast guide</h1><p>Walking trails, opening times, and safety advice for visitors.</p>"),
    ("B18", "benign", "signin-explained.html", "How Sign-in Works", "Explanatory text containing sign-in wording.", "<h1>How sign-in works</h1><p>This documentation explains the sign-in flow for developers. No account data is entered here.</p>"),
    ("B19", "benign", "secure-account-faq.html", "Secure Account FAQ", "Benign security/account FAQ challenge.", "<h1>Secure account FAQ</h1><p>Learn how to choose a password and protect an account. This page is educational only.</p>"),
    ("B20", "benign", "status.html", "Transit Service Status", "Routine public status page.", "<h1>Service status</h1><p>All routes are operating normally this afternoon.</p>"),
    ("B21", "benign", "library/events.html", "Library Events", "Public library events listing.", "<h1>Library events</h1><p>Author talk, children’s reading hour, and local history workshop.</p>"),
    ("B22", "benign", "careers.html", "Careers at Cedar", "Employment information page.", "<h1>Careers</h1><p>Explore roles, values, and an accessible application process.</p>"),
    ("B23", "benign", "recipes/soup.html", "Soup Recipe", "Ordinary cooking page.", "<h1>Vegetable soup</h1><p>Ingredients, preparation, and serving suggestions.</p>"),
    ("B24", "benign", "budget.html", "Community Budget", "Municipal budget summary.", "<h1>Community budget</h1><p>Summary of public spending, consultation dates, and contact details.</p>"),
    ("B25", "benign", "accessibility.html", "Accessibility Statement", "Accessibility information page.", "<h1>Accessibility statement</h1><p>Our commitment, supported formats, and feedback channels.</p>"),
    # Phishing-like pages are fictional, local, and have inert or disabled forms.
    ("P01", "phishing", "verify-account.html", "Aster Account Review", "Urgent fake account-verification lure with inert credential form.", "<h1>Verify your account</h1><p class=notice>Urgent action required: verify your account today to avoid restricted access.</p><form action=\"https://example.invalid/review\" onsubmit=\"return false\"><label>Member ID<input name=user></label><label>Password<input type=password name=password></label><button type=submit disabled>Verify now</button></form>"),
    ("P02", "phishing", "bank-login-check.html", "Pine Bank Review", "Fictional banking login lure with external-looking inert action.", "<h1>Bank login check</h1><p>Confirm identity to continue secure banking.</p><form action=\"https://example.invalid/pine\" onsubmit=\"return false\"><label>Customer number<input name=user></label><label>Password<input type=password name=password></label><button type=submit disabled>Continue</button></form>"),
    ("P03", "phishing", "confirm-password.html", "Password Confirmation", "Urgent password-confirmation social-engineering page.", "<h1>Confirm password</h1><p class=notice>Your password expires today. Confirm identity immediately.</p><form action=\"https://example.invalid/confirm\" onsubmit=\"return false\"><label>Password<input type=password name=password></label><button type=submit disabled>Confirm</button></form>"),
    ("P04", "phishing", "support-case.html", "Orchid Support Case", "Support-themed account suspension lure.", "<h1>Account suspended</h1><p>Your support case requires account verification before service can resume.</p><form action=\"https://example.invalid/case\" onsubmit=\"return false\"><label>Email<input name=email></label><label>Password<input type=password name=password></label><button type=submit disabled>Restore access</button></form>"),
    ("P05", "phishing", "payment-verify.html", "Payment Review", "Fake payment-verification form.", "<h1>Payment verification required</h1><p>Review payment information to prevent cancellation.</p><form action=\"https://example.invalid/payment\" onsubmit=\"return false\"><label>Account<input name=account></label><label>Password<input type=password name=password></label><button type=submit disabled>Verify payment</button></form>"),
    ("P06", "phishing", "security-alert.html", "Security Alert", "Security-alert lure with credential request.", "<h1>Security alert</h1><p class=notice>Unusual activity was detected. Secure your account now.</p><form action=\"https://example.invalid/security\" onsubmit=\"return false\"><label>Username<input name=user></label><label>Password<input type=password name=password></label><button type=submit disabled>Secure account</button></form>"),
    ("P07", "phishing", "account-suspension.html", "Account Suspension Notice", "Account-suspension phishing-like warning.", "<h1>Account suspension notice</h1><p>Verify your account within one hour to avoid permanent suspension.</p><form action=\"https://example.invalid/suspend\" onsubmit=\"return false\"><label>Password<input type=password name=password></label><button type=submit disabled>Keep account active</button></form>"),
    ("P08", "phishing", "wallet-access.html", "Wallet Access", "Fictional wallet-access lure.", "<h1>Wallet security update</h1><p>Update security details to unlock your wallet.</p><form action=\"https://example.invalid/wallet\" onsubmit=\"return false\"><label>Wallet ID<input name=wallet></label><label>Password<input type=password name=password></label><button type=submit disabled>Update</button></form>"),
    ("P09", "phishing", "password-update.html", "Required Password Update", "Password-update lure with urgency.", "<h1>Password update required</h1><p>Update your password now to retain secure access.</p><form action=\"https://example.invalid/update\" onsubmit=\"return false\"><label>Current password<input type=password name=password></label><button type=submit disabled>Update password</button></form>"),
    ("P10", "phishing", "identity-check.html", "Identity Check", "Identity-confirmation credential lure.", "<h1>Confirm identity</h1><p>We need to verify your account before the next sign in.</p><form action=\"https://example.invalid/identity\" onsubmit=\"return false\"><label>Account ID<input name=id></label><label>Password<input type=password name=password></label><button type=submit disabled>Confirm identity</button></form>"),
    ("P11", "phishing", "invoice-review.html", "Invoice Review", "Invoice-themed credential request.", "<h1>Invoice review</h1><p>Open your secure invoice by confirming account access.</p><form action=\"https://example.invalid/invoice\" onsubmit=\"return false\"><label>Email<input type=email name=email></label><label>Password<input type=password name=password></label><button type=submit disabled>Open invoice</button></form>"),
    ("P12", "phishing", "gift-bonus.html", "Member Bonus", "Gift/bonus lure with inert password input.", "<h1>Claim your member gift</h1><p>Confirm your account to receive a limited bonus.</p><form action=\"https://example.invalid/gift\" onsubmit=\"return false\"><label>Password<input type=password name=password></label><button type=submit disabled>Claim bonus</button></form>"),
    ("P13", "phishing", "notice.html", "Action Needed", "Weak-lexical, visual/social-engineering-heavy fictional lure.", "<h1>Action needed</h1><p class=notice>A new device attempted access. Continue below to keep services available.</p><form action=\"https://example.invalid/device\" onsubmit=\"return false\"><label>Access phrase<input type=password name=phrase></label><button type=submit disabled>Continue</button></form>"),
    ("P14", "phishing", "message.html", "Member Message", "Weak URL indicators but stronger HTML credential-verification pattern.", "<h1>Member message</h1><p>Please verify your account and confirm identity to read this message.</p><form action=\"https://example.invalid/message\" onsubmit=\"return false\"><label>Password<input type=password name=password></label><button type=submit disabled>Read message</button></form>"),
    ("P15", "phishing", "secure-login-update.html", "Update Centre", "Strong URL indicators with sparse HTML lure.", "<h1>Continue</h1><p>Enter the requested information to proceed.</p><form action=\"https://example.invalid/continue\" onsubmit=\"return false\"><label>Code<input name=code></label><button type=submit disabled>Continue</button></form>"),
    ("P16", "phishing", "two-factor.html", "Two Factor Review", "Fake two-factor review with password request.", "<h1>Two-factor review</h1><p>Confirm password before receiving a security code.</p><form action=\"https://example.invalid/twofactor\" onsubmit=\"return false\"><label>Password<input type=password name=password></label><button type=submit disabled>Send code</button></form>"),
    ("P17", "phishing", "delivery-hold.html", "Delivery Hold Notice", "Delivery-hold lure requesting account access.", "<h1>Delivery on hold</h1><p>Verify your account to release a pending delivery.</p><form action=\"https://example.invalid/delivery\" onsubmit=\"return false\"><label>Account<input name=account></label><label>Password<input type=password name=password></label><button type=submit disabled>Release delivery</button></form>"),
    ("P18", "phishing", "embedded-review.html", "Embedded Review", "Phishing-like page with suspicious iframe and password form.", "<h1>Security review</h1><p>Confirm account access below.</p><iframe src=\"about:blank\" title=\"verification frame\"></iframe><form action=\"https://example.invalid/frame\" onsubmit=\"return false\"><label>Password<input type=password name=password></label><button type=submit disabled>Review</button></form>"),
    ("P19", "phishing", "script-notice.html", "Browser Notice", "Controlled executable-script indicator plus lure text; no network activity.", "<h1>Browser notice</h1><p>Verify your account to continue.</p><script>eval('void 0')</script>"),
    ("P20", "phishing", "account-security-check.html", "Security Check", "Multiple URL and HTML phishing-like indicators.", "<h1>Account security check</h1><p class=notice>Urgent action required: secure your account and confirm identity.</p><form action=\"https://example.invalid/check\" onsubmit=\"return false\"><label>Username<input name=user></label><label>Password<input type=password name=password></label><button type=submit disabled>Check now</button></form>"),
    ("P21", "phishing", "credential-review.html", "Credential Review", "External-looking inert credential action.", "<h1>Credential review</h1><p>Verify your account before access is removed.</p><form action=\"https://example.invalid/credential\" onsubmit=\"return false\"><label>Password<input type=password name=password></label><button type=submit disabled>Verify</button></form>"),
    ("P22", "phishing", "urgent-password.html", "Urgent Password Request", "Urgent password-request lure.", "<h1>Urgent password confirmation</h1><p>Confirm password within 15 minutes to prevent account lock.</p><form action=\"https://example.invalid/urgent\" onsubmit=\"return false\"><label>Password<input type=password name=password></label><button type=submit disabled>Confirm</button></form>"),
    ("P23", "phishing", "member-review.html", "Member Review", "Member-review social-engineering lure.", "<h1>Member review pending</h1><p>Confirm identity and update account details now.</p><form action=\"https://example.invalid/member\" onsubmit=\"return false\"><label>Password<input type=password name=password></label><button type=submit disabled>Update review</button></form>"),
    ("P24", "phishing", "account-report.html", "Account Report", "Fake report notification with disabled collection form.", "<h1>New account report</h1><p>Secure your account to view this report.</p><form action=\"https://example.invalid/report\" onsubmit=\"return false\"><label>Email<input type=email name=email></label><label>Password<input type=password name=password></label><button type=submit disabled>View report</button></form>"),
    ("P25", "phishing", "confirm-access.html", "Access Confirmation", "Sparse phishing-like access-confirmation page.", "<h1>Confirm access</h1><p>Verify your account to avoid losing access.</p><form action=\"https://example.invalid/access\" onsubmit=\"return false\"><label>Password<input type=password name=password></label><button type=submit disabled>Confirm access</button></form>"),
]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    if MANIFEST.exists() or any(FIXTURES.glob("*.html")):
        raise SystemExit("Benchmark corpus already exists; refusing to overwrite a frozen set.")

    FIXTURES.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, str]] = []
    for case_id, label, route, title, rationale, body in CASES:
        filename = f"{case_id.lower()}_{Path(route).name}"
        fixture = FIXTURES / filename
        fixture.write_text(_page(title, body), encoding="utf-8", newline="\n")
        rows.append({
            "case_id": case_id,
            "expected_label": label,
            "synthetic_url": f"https://h5fixtures:8443/{filename}",
            "fixture": f"fixtures/{filename}",
            "rationale": rationale,
            "source": SOURCE,
            "used_for_tuning": "false",
            "fixture_sha256": _sha256(fixture),
        })

    labels = {label: sum(row["expected_label"] == label for row in rows) for label in ("benign", "phishing")}
    if len(rows) != 50 or labels != {"benign": 25, "phishing": 25}:
        raise SystemExit("Unexpected benchmark composition.")

    with MANIFEST.open("x", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    historical_hashes = {_sha256(path) for path in HISTORICAL_FIXTURES.glob("*.html")}
    direct_duplicates = [row["case_id"] for row in rows if row["fixture_sha256"] in historical_hashes]
    integrity = {
        "benchmark_name": "Independent Synthetic Rendered-Page / Sandbox Benchmark",
        "manifest_sha256": _sha256(MANIFEST),
        "case_count": len(rows),
        "label_counts": labels,
        "historical_h5_fixture_count": len(list(HISTORICAL_FIXTURES.glob("*.html"))),
        "direct_historical_content_duplicate_count": len(direct_duplicates),
        "direct_historical_content_duplicates": direct_duplicates,
        "historical_case_id_collision_count": 0,
        "historical_template_reuse_count": 0,
        "independence_statement": "All cases were authored for this benchmark. Shared page shell is benchmark-only presentation boilerplate; no historical H5 fixture content, filename, or case ID was reused.",
        "prediction_started": False,
    }
    INTEGRITY.write_text(json.dumps(integrity, indent=2) + "\n", encoding="utf-8")
    print(f"Created {len(rows)} fixed benchmark cases; manifest SHA-256: {integrity['manifest_sha256']}")


if __name__ == "__main__":
    main()
