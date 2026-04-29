"""
Feed 2 — Emerging Threats (ProofPoint)
No API key required
"""

import logging
import requests
from typing import List
from .base import BaseFeed

log = logging.getLogger("feeds.emergingthreats")

ET_COMPROMISED_URL = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"


class EmergingThreatsFeed(BaseFeed):

    name = "emergingthreats"

    def fetch(self) -> List[dict]:
        log.info("Fetching Emerging Threats blocklist...")

        try:
            response = requests.get(
                ET_COMPROMISED_URL,
                timeout=30,
                headers={"User-Agent": "TIP-Research/1.0"},
            )
            response.raise_for_status()

            indicators = []
            lines = response.text.splitlines()
            log.info("Downloaded %d lines", len(lines))

            for line in lines:
                line = line.strip()

                if not line or line.startswith("#"):
                    continue

                indicators.append({
                    "indicator": line,
                    "type": "ip",
                    "categories": ["compromised", "malware"],
                    "description": "Emerging Threats — known compromised host",
                    "score": 80,
                    "tags": ["compromised", "et-blocklist"],
                })

            log.info("Parsed %d valid IPs", len(indicators))
            return indicators

        except requests.exceptions.ConnectionError:
            log.error("Cannot reach Emerging Threats.")
            return []
        except Exception as exc:
            log.error("Emerging Threats fetch error: %s", exc)
            return []
