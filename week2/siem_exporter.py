"""
Week 2 — SIEM Exporter
MongoDB -> Elasticsearch
"""

import os
import sys
import argparse
import logging
from datetime import datetime, timezone

from dotenv import load_dotenv
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [%(levelname)-8s]  %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("week2.siem_exporter")

# Add week1 to path so we can reuse MongoStore
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "week1"))

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/threat_intel")
ES_HOST   = os.getenv("ELASTICSEARCH_HOST", "http://localhost:9200")


def add_risk_level(doc: dict) -> dict:
    score = doc.get("risk_score", 0)
    if score >= 90:
        doc["risk_level"] = "CRITICAL"
    elif score >= 70:
        doc["risk_level"] = "HIGH"
    elif score >= 50:
        doc["risk_level"] = "MEDIUM"
    else:
        doc["risk_level"] = "LOW"
    return doc


def prepare_for_es(mongo_doc: dict) -> dict:
    doc = dict(mongo_doc)

    # Remove MongoDB internal fields
    doc.pop("_id", None)
    doc.pop("raw", None)

    # Rename fields
    if "type" in doc:
        doc["indicator_type"] = doc.pop("type")
    if "source" in doc:
        doc["feed_source"] = doc.pop("source")
    if "blocked" in doc:
        doc["is_blocked"] = doc.pop("blocked")

    # Set timestamp
    last_seen = doc.get("last_seen")
    if last_seen:
        if isinstance(last_seen, datetime):
            doc["@timestamp"] = last_seen.isoformat()
        else:
            doc["@timestamp"] = str(last_seen)
    else:
        doc["@timestamp"] = datetime.now(timezone.utc).isoformat()

    # Add risk level
    doc = add_risk_level(doc)

    return doc


def run_export(mongo_store, es_client, min_score: int = 0, dry_run: bool = False):
    start = datetime.utcnow()
    log.info("=" * 60)
    log.info("SIEM Export started at %s UTC", start.strftime("%Y-%m-%d %H:%M:%S"))
    log.info("Min score: %d | Mode: %s", min_score, "DRY RUN" if dry_run else "LIVE")
    log.info("=" * 60)

    if min_score > 0:
        docs = mongo_store.get_high_risk(threshold=min_score, limit=10000)
    else:
        docs = mongo_store.get_all(limit=10000)

    log.info("Fetched %d indicators from MongoDB", len(docs))

    if not docs:
        log.info("Nothing to export.")
        return

    es_docs = [prepare_for_es(doc) for doc in docs]

    if dry_run:
        log.info("DRY RUN — sample output (first 3):")
        for doc in es_docs[:3]:
            log.info("  -> %s | type=%s | score=%d | level=%s",
                     doc.get("indicator"),
                     doc.get("indicator_type"),
                     doc.get("risk_score", 0),
                     doc.get("risk_level"))
        log.info("Would export %d total documents", len(es_docs))
        return

    indexed = es_client.bulk_index(es_docs)

    elapsed = (datetime.utcnow() - start).total_seconds()
    log.info("=" * 60)
    log.info("Export complete: %d/%d indexed in %.1fs", indexed, len(docs), elapsed)

    stats = es_client.get_risk_stats()
    if stats:
        log.info("Elasticsearch stats:")
        log.info("  Total docs : %d", stats.get("total", 0))
        log.info("  Avg score  : %s", stats.get("avg_risk_score", 0))
        log.info("  By level   : %s", stats.get("by_risk_level", {}))
    log.info("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="Week 2 SIEM Exporter")
    parser.add_argument("--loop",    action="store_true")
    parser.add_argument("--since",   type=int, default=0, metavar="SCORE")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    from db.mongo import MongoStore
    log.info("Connecting to MongoDB...")
    mongo_store = MongoStore(MONGO_URI)

    if not args.dry_run:
        from siem.es_client import ESClient
        log.info("Connecting to Elasticsearch: %s", ES_HOST)
        try:
            es_client = ESClient(ES_HOST)
        except Exception as e:
            log.error("Cannot connect to Elasticsearch: %s", e)
            log.error("Start ELK: docker compose -f elk_configs/docker-compose-elk.yml up -d")
            sys.exit(1)
    else:
        es_client = None

    if args.loop:
        import schedule, time
        log.info("Loop mode: every 5 minutes")
        run_export(mongo_store, es_client, min_score=args.since, dry_run=args.dry_run)
        schedule.every(5).minutes.do(
            run_export,
            mongo_store=mongo_store,
            es_client=es_client,
            min_score=args.since,
            dry_run=args.dry_run,
        )
        while True:
            schedule.run_pending()
            time.sleep(30)
    else:
        run_export(mongo_store, es_client, min_score=args.since, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
