"""
Feed 4 — VirusTotal
Needs API key: https://www.virustotal.com -> Profile -> API Key
"""

import logging
import time
import requests
from typing import List
from .base import BaseFeed

log = logging.getLogger("feeds.virustotal")

VT_API_BASE = "https://www.virustotal.com/api/v3"
FREE_TIER_SLEEP = 16


class VirusTotalFeed(BaseFeed):

    name = "virustotal"

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            "x-apikey": api_key,
            "User-Agent": "TIP-Research/1.0",
        })

    def fetch(self) -> List[dict]:
        log.info("Fetching from VirusTotal...")
        indicators = []

        search_queries = [
            "entity:ip detections:10+ tag:malware",
            "entity:ip detections:10+ tag:botnet",
        ]

        for query in search_queries:
            try:
                log.info("  VT query: '%s'", query)
                resp = self.session.get(
                    f"{VT_API_BASE}/search",
                    params={"query": query, "limit": 20},
                    timeout=30,
                )
                resp.raise_for_status()
                data = resp.json()

                for item in data.get("data", []):
                    attrs     = item.get("attributes", {})
                    stats     = attrs.get("last_analysis_stats", {})
                    total     = sum(stats.values()) or 1
                    malicious = stats.get("malicious", 0) + stats.get("suspicious", 0)
                    ratio     = malicious / total

                    indicators.append({
                        "indicator":    item.get("id"),
                        "type":         "ip",
                        "categories":   list(attrs.get("tags", [])),
                        "description":  f"VirusTotal: {malicious}/{total} engines flagged",
                        "score":        int(ratio * 100),
                        "vt_positives": malicious,
                        "vt_total":     total,
                        "country":      attrs.get("country"),
                        "tags":         list(attrs.get("tags", [])),
                    })

                log.info("  Got %d results", len(data.get("data", [])))
                log.info("  Sleeping %ds for rate limit...", FREE_TIER_SLEEP)
                time.sleep(FREE_TIER_SLEEP)

            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 401:
                    log.error("VirusTotal API key rejected. Check .env")
                elif e.response.status_code == 429:
                    log.warning("VirusTotal rate limit hit. Sleeping 60s...")
                    time.sleep(60)
                else:
                    log.error("VirusTotal HTTP error: %s", e)
                break
            except Exception as exc:
                log.error("VirusTotal fetch error: %s", exc)
                break

        log.info("VirusTotal total indicators: %d", len(indicators))
        return indicators
