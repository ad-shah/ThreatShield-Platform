"""
Feed 3 — AlienVault OTX
Needs API key: https://otx.alienvault.com -> Settings -> API Key
"""

import logging
import requests
from datetime import datetime, timedelta, timezone
from typing import List
from .base import BaseFeed

log = logging.getLogger("feeds.otx")

OTX_API_BASE = "https://otx.alienvault.com/api/v1"

OTX_TYPE_MAP = {
    "IPv4":            "ip",
    "IPv6":            "ip",
    "domain":          "domain",
    "hostname":        "domain",
    "URL":             "url",
    "FileHash-MD5":    "hash",
    "FileHash-SHA1":   "hash",
    "FileHash-SHA256": "hash",
    "email":           None,
    "CVE":             None,
}


class OTXFeed(BaseFeed):

    name = "alienvault_otx"

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            "X-OTX-API-KEY": api_key,
            "User-Agent": "TIP-Research/1.0",
        })

    def fetch(self) -> List[dict]:
        since = (datetime.now(timezone.utc) - timedelta(days=7))
        since_str = since.strftime("%Y-%m-%dT%H:%M:%S")

        log.info("Fetching OTX pulses since %s", since_str)

        all_indicators = []
        page = 1

        while True:
            try:
                resp = self.session.get(
                    f"{OTX_API_BASE}/pulses/subscribed",
                    params={
                        "modified_since": since_str,
                        "page": page,
                        "limit": 50,
                    },
                    timeout=30,
                )
                resp.raise_for_status()
                data = resp.json()

                pulses = data.get("results", [])
                if not pulses:
                    break

                log.info("  Page %d: %d pulses", page, len(pulses))

                for pulse in pulses:
                    pulse_name = pulse.get("name", "Unknown")
                    pulse_tags = pulse.get("tags", [])

                    for ind in pulse.get("indicators", []):
                        otx_type = ind.get("type", "")
                        standard_type = OTX_TYPE_MAP.get(otx_type)

                        if standard_type is None:
                            continue

                        all_indicators.append({
                            "indicator":   ind.get("indicator"),
                            "type":        standard_type,
                            "categories":  pulse_tags,
                            "description": f"OTX Pulse: {pulse_name}",
                            "tags":        pulse_tags,
                            "first_seen":  ind.get("created"),
                            "pulse_name":  pulse_name,
                        })

                if not data.get("next"):
                    break
                page += 1

            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 403:
                    log.error("OTX API key invalid. Check OTX_API_KEY in .env")
                else:
                    log.error("OTX HTTP error page %d: %s", page, e)
                break
            except Exception as exc:
                log.error("OTX fetch error page %d: %s", page, exc)
                break

        log.info("OTX total indicators: %d", len(all_indicators))
        return all_indicators
