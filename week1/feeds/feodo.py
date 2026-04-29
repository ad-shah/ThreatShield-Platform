"""
Feed 1 — Feodo Tracker (Abuse.ch)
No API key required
"""

import logging
import requests
from typing import List
from .base import BaseFeed

log = logging.getLogger("feeds.feodo")

FEODO_JSON_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.json"


class FeodoFeed(BaseFeed):

    name = "feodo"

    def fetch(self) -> List[dict]:
        log.info("Fetching Feodo C2 blocklist...")

        try:
            response = requests.get(
                FEODO_JSON_URL,
                timeout=30,
                headers={"User-Agent": "TIP-Research/1.0"},
            )
            response.raise_for_status()

            raw_list = response.json()
            log.info("Fetched %d Feodo records", len(raw_list))

            indicators = []
            for entry in raw_list:
                indicators.append({
                    "indicator": entry.get("ip_address"),
                    "type": "ip",
                    "categories": [
                        "botnet",
                        "c2",
                        entry.get("malware", "unknown").lower(),
                    ],
                    "description": (
                        f"Feodo C2 server — {entry.get('malware','?')} botnet, "
                        f"port {entry.get('port','?')}, "
                        f"status: {entry.get('status','?')}"
                    ),
                    "score": 95,
                    "tags": ["botnet", "c2", entry.get("malware", "").lower()],
                    "first_seen": entry.get("first_seen"),
                    "country": entry.get("country"),
                    "port": entry.get("port"),
                    "malware_family": entry.get("malware"),
                })

            return indicators

        except requests.exceptions.ConnectionError:
            log.error("Cannot reach Feodo. Check internet connection.")
            return []
        except requests.exceptions.Timeout:
            log.error("Feodo request timed out.")
            return []
        except Exception as exc:
            log.error("Unexpected error fetching Feodo: %s", exc)
            return []
