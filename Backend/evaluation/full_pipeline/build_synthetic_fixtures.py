"""Create the fixed, inert fixture corpus for the offline full-pipeline evaluation.

The corpus is deliberately synthetic and is generated from this checked-in
case definition.  ``.example`` and ``.invalid`` are reserved domains; no case
is fetched, opened in a browser, or submitted.  Password forms are disabled
and include an ``onsubmit`` cancellation solely to keep them inert even if a
developer accidentally opens a fixture locally.
"""

from __future__ import annotations

import csv
from pathlib import Path


ROOT = Path(__file__).resolve().parent
FIXTURES = ROOT / "fixtures"
MANIFEST = ROOT / "manifest.csv"
SOURCE = "synthetic_offline_evaluation"


def page(title: str, body: str) -> str:
    return f"<!doctype html><html><head><meta charset=\"utf-8\"><title>{title}</title></head><body>{body}</body></html>\n"


def inert_password_form(copy: str, action: str = "#") -> str:
    return (
        f"<form action=\"{action}\" method=\"post\" onsubmit=\"return false\" data-test-only=\"true\">"
        f"<p>{copy}</p><label>Email <input type=\"email\" disabled></label>"
        "<label>Password <input type=\"password\" disabled autocomplete=\"off\"></label>"
        "<button type=\"submit\" disabled>Continue</button></form>"
    )


BENIGN = [
    ("B01", "https://search.example/catalog", "search_page", "Static site-search model; no credential collection.", page("Catalog search", "<h1>Catalog search</h1><form action=\"#\" onsubmit=\"return false\"><input type=\"search\" disabled><button disabled>Search</button></form>")),
    ("B02", "https://docs.example/getting-started", "documentation_page", "Ordinary product documentation.", page("Getting started", "<h1>Getting started</h1><p>Install the desktop client and read the guide.</p>")),
    ("B03", "https://university.example/admissions", "university_page", "University admissions information only.", page("Admissions", "<h1>Admissions</h1><p>Programme dates, campus tours, and application guidance.</p>")),
    ("B04", "https://shop.example/products/linen-notebook", "ecommerce_product", "Product listing with a non-credential cart control.", page("Linen notebook", "<h1>Linen notebook</h1><p>Blue cover, recycled paper.</p><button disabled>Add to basket</button>")),
    ("B05", "https://journal.example/articles/growing-herbs", "blog_article", "Normal editorial article.", page("Growing herbs", "<article><h1>Growing herbs indoors</h1><p>Choose a sunny window and water consistently.</p></article>")),
    ("B06", "https://member.example/dashboard", "account_dashboard", "Read-only member dashboard without a form.", page("Dashboard", "<h1>Welcome back</h1><p>Your deliveries and preferences are available here.</p>")),
    ("B07", "https://portal.example/signin", "ordinary_login", "Legitimate-style ordinary login represented locally and inertly.", page("Member sign in", inert_password_form("Enter your member details to access saved preferences."))),
    ("B08", "https://help.example/reset", "password_reset", "Legitimate-style reset page represented locally and inertly.", page("Reset access", inert_password_form("Choose a new passphrase for your local demonstration profile."))),
    ("B09", "https://creditunion.example/services", "banking_information", "Local banking-services information, not a collection page.", page("Everyday services", "<h1>Everyday services</h1><p>Read about savings, cards, branch hours, and fees.</p>")),
    ("B10", "https://support.example/contact", "contact_support", "Support contact form without credentials.", page("Contact support", "<form action=\"#\" onsubmit=\"return false\"><label>Message <textarea disabled></textarea></label><button disabled>Send</button></form>")),
    ("B11", "https://weather.example/colombo", "weather_page", "Informational weather forecast.", page("Forecast", "<h1>Forecast</h1><p>Sunshine in the morning; rain later in the day.</p>")),
    ("B12", "https://recipes.example/soup", "recipe_page", "Static cooking recipe.", page("Vegetable soup", "<h1>Vegetable soup</h1><ol><li>Chop vegetables</li><li>Simmer</li></ol>")),
    ("B13", "https://library.example/events", "library_events", "Public library events listing.", page("Library events", "<h1>Events</h1><p>Story time on Saturday and a book club on Tuesday.</p>")),
    ("B14", "https://travel.example/guide/coast", "travel_guide", "Travel guide with no transactional fields.", page("Coast guide", "<h1>Coast guide</h1><p>Plan transport, lodging, and walking routes.</p>")),
    ("B15", "https://status.example/", "service_status", "Routine public service-status page.", page("Service status", "<h1>All systems operational</h1><p>Last checked this morning.</p>")),
    ("B16", "https://forum.example/topics/gardening", "forum_topic", "Static discussion rendering.", page("Gardening discussion", "<h1>Gardening discussion</h1><p>Members discuss compost and seasonal plants.</p>")),
    ("B17", "https://museum.example/exhibits/maps", "museum_page", "Museum exhibit information.", page("Maps exhibition", "<h1>Maps through time</h1><p>Open Tuesday through Sunday.</p>")),
    ("B18", "https://news.example/local/market", "news_article", "Normal news article.", page("Market opens", "<article><h1>Market opens</h1><p>Local growers return for the spring season.</p></article>")),
    ("B19", "https://fitness.example/classes", "fitness_schedule", "Class schedule and booking information.", page("Class schedule", "<h1>Classes</h1><p>Yoga at 08:00; strength training at 18:00.</p>")),
    ("B20", "https://calendar.example/events", "community_calendar", "Community event list.", page("Community calendar", "<h1>Calendar</h1><p>Concert, lecture, and clean-up day.</p>")),
    ("B21", "https://files.example/share/guide", "file_share_landing", "Static file-share landing page with no collection action.", page("Shared guide", "<h1>Shared guide</h1><p>A local sample document is ready for review.</p>")),
    ("B22", "https://education.example/course/history", "course_page", "Online-course informational page.", page("History course", "<h1>History course</h1><p>Week one covers early trade routes.</p>")),
    ("B23", "https://music.example/playlists/jazz", "music_page", "Playlist description only.", page("Jazz playlist", "<h1>Evening jazz</h1><p>A curated instrumental playlist.</p>")),
    ("B24", "https://volunteer.example/opportunities", "volunteer_page", "Volunteer-opportunity listing.", page("Volunteer opportunities", "<h1>Volunteer</h1><p>Help with park care or food distribution.</p>")),
    ("B25", "https://knowledge.example/faq", "faq_page", "Frequently asked questions without a credential form.", page("Frequently asked questions", "<h1>FAQ</h1><p>Find answers about delivery and returns.</p>")),
]

PHISHING = [
    ("P01", "https://secure-verify-login.example/continue", "urgent_verification_form", "Synthetic urgent credential-verification pattern.", page("Action required", inert_password_form("Urgent action required: verify your account to continue.", "https://collector.invalid/receive"))),
    ("P02", "https://bank-login-check.example/session", "fake_banking_login", "Synthetic banking-login wording with external-looking inert form action.", page("Bank login", inert_password_form("Bank login: confirm identity before access.", "https://collector.invalid/bank"))),
    ("P03", "https://wallet-security-update.example/", "wallet_security_form", "Synthetic wallet security update pattern.", page("Wallet notice", inert_password_form("Security alert: verify your account now.", "https://collector.invalid/wallet"))),
    ("P04", "http://confirm-account.example/", "http_confirmation", "Synthetic non-HTTPS confirmation lure.", page("Confirmation", inert_password_form("Confirm identity to restore your account.", "https://collector.invalid/confirm"))),
    ("P05", "https://paypa1-billing-login.example/", "brand_typosquat_pattern", "Synthetic lookalike-style URL and credential request.", page("Billing centre", inert_password_form("Sign in to continue and verify your account.", "https://collector.invalid/billing"))),
    ("P06", "https://free-gift-claim.example/reward", "reward_lure", "Synthetic reward lure with credential request.", page("Reward", inert_password_form("Claim reward now. Limited time offer.", "https://collector.invalid/reward"))),
    ("P07", "https://crypto-wallet-verify.example/", "crypto_wallet_lure", "Synthetic crypto-wallet verification pattern.", page("Wallet verification", inert_password_form("Verify your account to protect your wallet.", "https://collector.invalid/crypto"))),
    ("P08", "https://signin-security-alert.example/", "security_alert", "Synthetic sign-in security-alert pattern.", page("Security alert", inert_password_form("Security alert. Re-enter your password.", "https://collector.invalid/alert"))),
    ("P09", "https://account-check.example/", "credential_iframe", "Synthetic credential lure containing a structural iframe.", page("Review needed", inert_password_form("Verify your account.", "https://collector.invalid/review") + "<iframe src=\"about:blank\" title=\"test-only\"></iframe>")),
    ("P10", "https://verify.example/document", "script_obfuscation_indicator", "Synthetic verification lure with an eval indicator in executable script.", page("Document review", inert_password_form("Verify your account.", "https://collector.invalid/document") + "<script>eval('0');</script>")),
    ("P11", "https://secure-update.example/customer", "external_password_action", "External-looking inert password-form submission indicator.", page("Update", inert_password_form("Update your details.", "https://collector.invalid/update"))),
    ("P12", "https://login-review.example/", "identity_confirmation", "Synthetic identity-confirmation lure.", page("Identity review", inert_password_form("Confirm your identity. Urgent action required.", "https://collector.invalid/identity"))),
    ("P13", "https://bank-secure-access.example/", "bank_security_lure", "Synthetic banking security wording.", page("Secure access", inert_password_form("Bank login. Security alert.", "https://collector.invalid/access"))),
    ("P14", "https://password-reset-notice.example/", "reset_lure", "Synthetic password-reset lure.", page("Reset notice", inert_password_form("Password reset required. Verify your account.", "https://collector.invalid/reset"))),
    ("P15", "https://bonus-confirm.example/", "bonus_lure", "Synthetic bonus confirmation lure.", page("Bonus confirmation", inert_password_form("Confirm identity to claim reward.", "https://collector.invalid/bonus"))),
    ("P16", "https://secure-login-verify.example/", "multi_signal_lure", "Synthetic multi-signal credential page.", page("Verify", inert_password_form("Verify your account. Security alert. Limited time offer.", "https://collector.invalid/multi") + "<iframe src=\"about:blank\"></iframe><script>eval('0');</script>")),
    ("P17", "https://update-customer-security.example/", "suspicious_url_and_form", "Synthetic update/security credential page.", page("Customer update", inert_password_form("Sign in to continue. Security alert.", "https://collector.invalid/customer"))),
    ("P18", "https://login-verify-center.example/", "verification_centre", "Synthetic login-verification centre.", page("Verification centre", inert_password_form("Verify account access now.", "https://collector.invalid/centre"))),
    ("P19", "https://gift-account-check.example/", "gift_account_lure", "Synthetic gift-account lure.", page("Gift eligibility", inert_password_form("Claim reward. Verify your account.", "https://collector.invalid/gift"))),
    ("P20", "https://security-confirm-login.example/", "confirmation_lure", "Synthetic security confirmation lure.", page("Confirmation needed", inert_password_form("Confirm your password. Security alert.", "https://collector.invalid/security"))),
    ("P21", "https://portal.example/notice", "misleading_link_only", "Synthetic misleading-link lure intentionally lacking scored URL/form indicators.", page("Document available", "<h1>New document</h1><p>Open the shared statement.</p><a href=\"https://collector.invalid/review\">View document</a>")),
    ("P22", "https://support.example/notice", "callback_lure_only", "Synthetic callback lure intentionally lacking scored HTML indicators.", page("Customer notice", "<h1>Please call our desk</h1><p>A representative is waiting at 555-0100.</p>")),
    ("P23", "https://portal.example/files", "attachment_lure_only", "Synthetic attachment lure intentionally lacking scored indicators.", page("Shared file", "<h1>Shared file</h1><a href=\"https://collector.invalid/file\">Open attachment</a>")),
    ("P24", "https://notice.example/receipt", "visual_impersonation_only", "Synthetic visual-impersonation-style page with no implemented lexical or structural signal.", page("Receipt", "<h1>Recent receipt</h1><p>Review the attached record.</p><a href=\"https://collector.invalid/record\">Review record</a>")),
    ("P25", "https://service.example/message", "embedded_content_lure", "Synthetic embedded-content lure; an iframe is an explicit implemented signal.", page("Message", "<h1>New message</h1><iframe src=\"about:blank\" title=\"test-only\"></iframe>")),
]


def main() -> None:
    FIXTURES.mkdir(parents=True, exist_ok=True)
    rows = []
    for label, cases in (("benign", BENIGN), ("phishing", PHISHING)):
        for case_id, url, category, rationale, html in cases:
            filename = f"{case_id.lower()}_{category}.html"
            (FIXTURES / filename).write_text(html, encoding="utf-8")
            rows.append({"case_id": case_id, "expected_label": label, "synthetic_url": url, "local_html_fixture_path": f"fixtures/{filename}", "rationale": rationale, "source": SOURCE})
    with MANIFEST.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["case_id", "expected_label", "synthetic_url", "local_html_fixture_path", "rationale", "source"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {len(rows)} inert fixtures and {MANIFEST}")


if __name__ == "__main__":
    main()
