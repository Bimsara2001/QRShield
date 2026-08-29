import requests
import base64
import os

API_KEY_ENV = "VIRUSTOTAL_API_KEY"


def _api_key():
    return os.environ.get(API_KEY_ENV, "").strip()

def check_url_virustotal(url):

    api_key = _api_key()
    if not api_key:
        return {
            "status": "disabled",
            "message": "VirusTotal integration is not configured"
        }

    try:

        url_id = base64.urlsafe_b64encode(
            url.encode()
        ).decode().strip("=")

        headers = {
            "x-apikey": api_key
        }

        vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        response = requests.get(
            vt_url,
            headers=headers
        )

        if response.status_code != 200:

            return {
                "status": "error",
                "message": "VirusTotal request failed"
            }

        data = response.json()

        stats = data["data"]["attributes"]["last_analysis_stats"]

        malicious = stats.get("malicious", 0)

        suspicious = stats.get("suspicious", 0)

        harmless = stats.get("harmless", 0)

        if malicious > 0:

            verdict = "DANGEROUS"

        elif suspicious > 0:

            verdict = "SUSPICIOUS"

        else:

            verdict = "SAFE"

        return {
            "status": "success",
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "verdict": verdict
        }

    except Exception as e:

        return {
            "status": "error",
            "message": str(e)
        }
