"""
Week 2 — IP Enrichment
Adds geo/country context to IP indicators
No API key required — uses ip-api.com
"""

import os
import sys
import time
import logging
import argparse
import requests
from datetime import datetime, timezone
from typing import Optional, List

from dotenv import load_dotenv
load_dotenv()

log = logging.getLogger("week2.enrichment")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [%(levelname)-8s]  %(name)s — %(message)s",
)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "week1"))

MONGO_URI    = os.getenv("MONGO_URI", "mongodb://localhost:27017/threat_intel")
IPAPI_BATCH  = "http://ip-api.com/batch"
RATE_LIMIT   = 45


def enrich_single_ip(ip: str) -> Optional[dict]:
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,countryCode,city,isp,org,as,query"},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()

        if data.get("status") != "success":
            return None

        return {
            "geo_country":      data.get("country"),
            "geo_country_code": data.get("countryCode"),
            "geo_city":         data.get("city"),
            "isp":              data.get("isp"),
            "org":              data.get("org"),
            "asn":              data.get("as"),
            "enriched_at":      datetime.now(timezone.utc),
        }

    except requests.exceptions.ConnectionError:
        log.warning("Cannot reach ip-api.com")
        return None
    except Exception as e:
        log.error("Enrichment error for %s: %s", ip, e)
        return None


def enrich_batch(ips: List[str]) -> dict:
    results = {}
    for i in range(0, len(ips), 100):
        chunk = ips[i:i+100]
        try:
            resp = requests.post(
                IPAPI_BATCH,
                json=[{
                    "query": ip,
                    "fields": "status,country,countryCode,city,isp,org,as,query"
                } for ip in chunk],
                timeout=30,
            )
            resp.raise_for_status()
            for entry in resp.json():
                if entry.get("status") == "success":
                    results[entry["query"]] = {
                        "geo_country":      entry.get("country"),
                        "geo_country_code": entry.get("countryCode"),
                        "geo_city":         entry.get("city"),
                        "isp":              entry.get("isp"),
                        "org":              entry.get("org"),
                        "asn":              entry.get("as"),
                        "enriched_at":      datetime.now(timezone.utc),
                    }
            time.sleep(len(chunk) / RATE_LIMIT * 60)
        except Exception as e:
            log.error("Batch enrichment error: %s", e)

    return results


def run_enrichment(limit: int = 500, dry_run: bool = False):
    from db.mongo import MongoStore
    store = MongoStore(MONGO_URI)

    un_enriched = list(
        store.indicators.find(
            {"type": "ip", "geo_country": {"$exists": False}},
            {"indicator": 1, "_id": 0},
        ).limit(limit)
    )

    if not un_enriched:
        log.info("All IP indicators already enriched!")
        return

    ips = [doc["indicator"] for doc in un_enriched]
    log.info("Enriching %d IP indicators...", len(ips))

    if dry_run:
        log.info("[DRY RUN] Would enrich: %s", ips[:5])
        return

    geo_data = enrich_batch(ips)

    updated = 0
    for ip, geo in geo_data.items():
        result = store.indicators.update_many(
            {"indicator": ip},
            {"$set": geo}
        )
        updated += result.modified_count

    log.info("Enrichment complete: %d IPs updated", updated)

    by_country = {}
    for geo in geo_data.values():
        cc = geo.get("geo_country_code", "??")
        by_country[cc] = by_country.get(cc, 0) + 1

    top = sorted(by_country.items(), key=lambda x: x[1], reverse=True)[:10]
    log.info("Top countries:")
    for cc, count in top:
        log.info("  %-5s : %d", cc, count)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit",   type=int, default=500)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    run_enrichment(limit=args.limit, dry_run=args.dry_run)
