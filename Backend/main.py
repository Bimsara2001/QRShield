from fastapi import FastAPI
from pydantic import BaseModel
from playwright.sync_api import sync_playwright
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

import uuid

from analyzer.risk_engine import analyze_url
from threat_intel.virustotal import check_url_virustotal
from detectors.phishing_detector import detect_phishing
from database import scan_collection

app = FastAPI()

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount screenshots folder
app.mount(
    "/screenshots",
    StaticFiles(directory="screenshots"),
    name="screenshots"
)


class URLRequest(BaseModel):
    url: str


# Home Route
@app.get("/")
def home():
    return {
        "message": "QRShield Sandbox Running"
    }


# Scan Route
@app.post("/scan")
def scan_url(data: URLRequest):

    url = data.url

    risk_score = 0
    reasons = []

    screenshot_name = f"{uuid.uuid4()}.png"
    screenshot_path = f"screenshots/{screenshot_name}"

    try:

        with sync_playwright() as p:

            browser = p.chromium.launch(
                headless=True
            )

            page = browser.new_page()

            page.goto(
                url,
                timeout=60000
            )

            html = page.content()

            phishing_result = detect_phishing(html)

            risk_score += phishing_result["score"]

            reasons.extend(
                phishing_result["reasons"]
            )

            page.screenshot(
                path=screenshot_path
            )

            final_url = page.url
            title = page.title()

            browser.close()

        risk_result = analyze_url(
            url,
            final_url
        )

        risk_result["score"] += risk_score

        risk_result["reasons"].extend(
            reasons
        )

        if risk_result["score"] >= 70:

            risk_result["verdict"] = "High Risk"

        elif risk_result["score"] >= 40:

            risk_result["verdict"] = "Medium Risk"

        else:

            risk_result["verdict"] = "Low Risk"

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

    except Exception as e:

        return {
            "status": "error",
            "message": str(e)
        }


# History API
@app.get("/history")
def get_scan_history():

    scans = list(
        scan_collection.find(
            {},
            {"_id": 0}
        ).sort("_id", -1)
    )

    return scans


# Clear History API
@app.delete("/history")
def clear_history():

    scan_collection.delete_many({})

    return {
        "status": "success",
        "message": "History cleared"
    }


# Stats API
@app.get("/stats")
def get_stats():

    scans = list(
        scan_collection.find(
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