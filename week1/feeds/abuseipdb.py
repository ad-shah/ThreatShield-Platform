"""
Feed 5 — AbuseIPDB
Needs API key: https://www.abuseipdb.com -> Account -> API
"""

import logging
import requests
from typing import List
from .base import BaseFeed

log = logging.getLogger("feeds.abuseipdb")

ABUSEIPDB_API_BASE = "https://api.abuseipdb.com/api/v2"

CATEGORY_NAMES = {
    3:  "fraud_orders",
    4:  "ddos_attack",
    5:  "ftp_brute_force",
    6:  "ping_of_death",
    7:  "phishing",
    9:  "open_proxy",
    10: "web_spam",
    11: "email_spam",
    14: "port_scan",
    15: "hacking",
    16: "sql_injection",
    17: "spoofing",
    18: "brute_force",
    19: "bad_web_bot",
    20: "exploited_host",
    21: "web_app_attack",
    22: "ssh_brute_force",
    23: "iot_targeted",
}


class AbuseIPDBFeed(BaseFeed):

    name = "abuseipdb"

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            "Key": api_key,
            "Accept": "application/json",
            "User-Agent": "TIP-Research/1.0",
        })

    def fetch(self) -> List[dict]:
        log.info("Fetching AbuseIPDB blacklist...")

        try:
            resp = self.session.get(
                f"{ABUSEIPDB_API_BASE}/blacklist",
                params={
                    "confidenceMinimum": 90,
                    "limit": 10000,
                    "plaintext": False,
                },
                timeout=60,
            )
            resp.raise_for_status()
            data = resp.json()

            indicators = []
            for entry in data.get("data", []):
                cat_ids    = entry.get("abuseCategories", [])
                categories = [CATEGORY_NAMES.get(c, f"category_{c}") for c in cat_ids]
                confidence = entry.get("abuseConfidenceScore", 50)

                indicators.append({
                    "indicator":  entry.get("ipAddress"),
                    "type":       "ip",
                    "categories": categories,
                    "description": f"AbuseIPDB: {confidence}% confidence",
                    "score":      min(100, confidence),
                    "country":    entry.get("countryCode"),
                    "first_seen": entry.get("lastReportedAt"),
                    "tags":       categories,
                })

            log.info("AbuseIPDB returned %d IPs", len(indicators))
            return indicators

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                log.error("AbuseIPDB key rejected. Check ABUSEIPDB_API_KEY in .env")
            elif e.response.status_code == 429:
                log.error("AbuseIPDB daily rate limit hit.")
            else:
                log.error("AbuseIPDB HTTP error: %s", e)
            return []
        except Exception as exc:
            log.error("AbuseIPDB fetch error: %s", exc)
            return []
