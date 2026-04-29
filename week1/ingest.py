import os
import sys
import argparse
import logging
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [%(levelname)-8s]  %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("logs/ingest.log"),
    ],
)
log = logging.getLogger("week1.ingest")

from feeds.feodo import FeodoFeed
from feeds.emergingthreats import EmergingThreatsFeed
from feeds.otx import OTXFeed
from feeds.virustotal import VirusTotalFeed
from feeds.abuseipdb import AbuseIPDBFeed
from normalizer import normalize_indicator
from db.mongo import MongoStore


def build_active_feeds(only=None):
    all_feeds = {
        "feodo":           (FeodoFeed,           None),
        "emergingthreats": (EmergingThreatsFeed,  None),
        "otx":             (OTXFeed,              os.getenv("OTX_API_KEY")),
        "virustotal":      (VirusTotalFeed,        os.getenv("VIRUSTOTAL_API_KEY")),
        "abuseipdb":       (AbuseIPDBFeed,         os.getenv("ABUSEIPDB_API_KEY")),
    }

    feeds = []
    for name, (cls, key) in all_feeds.items():
        if only and name != only:
            continue
        if key is None and cls not in (FeodoFeed, EmergingThreatsFeed):
            log.info("Skipping %-20s — no API key in .env", name)
            continue
        feeds.append(cls(key) if key else cls())
    return feeds


def run_once(store, feeds, dry_run=False):
    start = datetime.utcnow()
    log.info("=" * 60)
    log.info("Ingestion started at %s UTC", start.strftime("%Y-%m-%d %H:%M:%S"))
    log.info("Feeds: %s", [f.name for f in feeds])
    log.info("Mode: %s", "DRY RUN" if dry_run else "LIVE")
    log.info("=" * 60)

    summary = {}

    for feed in feeds:
        log.info("Polling feed: %s", feed.name.upper())
        try:
            raw_items = feed.fetch()
            log.info("  Raw records fetched    : %d", len(raw_items))

            normalized = []
            skipped = 0
            for raw in raw_items:
                result = normalize_indicator(raw, feed.name)
                if result:
                    normalized.append(result)
                else:
                    skipped += 1

            log.info("  Normalized successfully: %d", len(normalized))
            log.info("  Skipped                : %d", skipped)

            if dry_run:
                for ind in normalized[:3]:
                    log.info("  [DRY] %s | type=%-8s score=%d",
                             ind["indicator"], ind["type"], ind["risk_score"])
                upserted = len(normalized)
            else:
                upserted = store.upsert_indicators(normalized)
                log.info("  Saved to MongoDB       : %d", upserted)

            summary[feed.name] = {
                "fetched": len(raw_items),
                "saved": upserted,
                "skipped": skipped
            }

        except Exception as exc:
            log.error("Feed %s failed: %s", feed.name, exc, exc_info=True)
            summary[feed.name] = {"error": str(exc)}

    elapsed = (datetime.utcnow() - start).total_seconds()
    log.info("")
    log.info("=" * 60)
    log.info("INGESTION SUMMARY  (%.1fs elapsed)", elapsed)
    log.info("=" * 60)
    log.info("  %-24s  %-10s %-10s", "Feed", "Fetched", "Saved")
    log.info("  %-24s  %-10s %-10s", "-"*24, "-"*10, "-"*10)

    for name, stats in summary.items():
        if "error" in stats:
            log.info("  %-24s  ERROR: %s", name, stats["error"])
        else:
            log.info("  %-24s  %-10d %-10d",
                     name, stats["fetched"], stats["saved"])

    if not dry_run and store:
        db_stats = store.get_stats()
        log.info("")
        log.info("  MongoDB totals:")
        log.info("    Total indicators : %d", db_stats["total"])
        log.info("    High-risk (>=70) : %d", db_stats["high_risk"])
        log.info("    By type          : %s", db_stats["by_type"])
    log.info("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="Week 1 OSINT Ingestion")
    parser.add_argument("--loop", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--feed", help="Run only one feed")
    args = parser.parse_args()

    feeds = build_active_feeds(only=args.feed)
    if not feeds:
        log.error("No feeds available!")
        sys.exit(1)

    if args.dry_run:
        store = None
    else:
        mongo_uri = os.getenv("MONGO_URI", "mongodb://localhost:27017/threat_intel")
        store = MongoStore(mongo_uri)

    if args.loop:
        import schedule, time
        interval = int(os.getenv("POLL_INTERVAL_MINUTES", 30))
        log.info("Loop mode: every %d minutes", interval)
        run_once(store, feeds, dry_run=args.dry_run)
        schedule.every(interval).minutes.do(
            run_once, store=store, feeds=feeds, dry_run=args.dry_run
        )
        while True:
            schedule.run_pending()
            time.sleep(60)
    else:
        run_once(store, feeds, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
