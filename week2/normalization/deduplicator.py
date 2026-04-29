"""
Week 2 — Cross-Feed Deduplication Report
"""

import os
import sys
import logging
import argparse
from collections import defaultdict

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("week2.deduplicator")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "week1"))

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/threat_intel")


def run_dedup_report(update_scores: bool = False):
    from db.mongo import MongoStore
    store = MongoStore(MONGO_URI)

    log.info("Loading all indicators...")
    all_docs = list(store.indicators.find(
        {}, {"indicator": 1, "source": 1, "risk_score": 1, "type": 1}
    ))
    log.info("Total documents: %d", len(all_docs))

    indicator_sources = defaultdict(list)
    for doc in all_docs:
        indicator_sources[doc["indicator"]].append({
            "source":     doc["source"],
            "risk_score": doc.get("risk_score", 0),
            "type":       doc.get("type"),
        })

    multi_source = {
        ind: sources
        for ind, sources in indicator_sources.items()
        if len(sources) > 1
    }

    print("\n" + "=" * 70)
    print("  CROSS-FEED DEDUPLICATION REPORT")
    print("=" * 70)
    print(f"  Total unique indicators : {len(indicator_sources)}")
    print(f"  Total documents         : {len(all_docs)}")
    print(f"  In 2+ feeds             : {len(multi_source)}")
    print("=" * 70)

    if multi_source:
        print("\n  TOP MULTI-SOURCE INDICATORS")
        print("  " + "-" * 66)
        sorted_multi = sorted(
            multi_source.items(),
            key=lambda x: len(x[1]),
            reverse=True
        )
        for indicator, sources in sorted_multi[:20]:
            names     = [s["source"] for s in sources]
            max_score = max(s["risk_score"] for s in sources)
            itype     = sources[0]["type"]
            print(f"  {indicator:<22} | {itype:<8} | "
                  f"{len(sources)} feeds | score={max_score} | "
                  f"{', '.join(names)}")

    if update_scores and multi_source:
        print(f"\n  Updating scores for {len(multi_source)} indicators...")
        boosted = 0
        for indicator, sources in multi_source.items():
            boost = min(20, (len(sources) - 1) * 5)
            for src in sources:
                new_score = min(100, src["risk_score"] + boost)
                store.indicators.update_one(
                    {"indicator": indicator, "source": src["source"]},
                    {"$set": {"risk_score": new_score, "source_count": len(sources)}}
                )
                boosted += 1
        print(f"  Updated {boosted} documents")

    print("\n  By indicator type:")
    type_counts = defaultdict(int)
    for sources in indicator_sources.values():
        type_counts[sources[0].get("type", "unknown")] += 1
    for itype, count in sorted(type_counts.items()):
        print(f"    {itype:<10} : {count}")
    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--update", action="store_true")
    args = parser.parse_args()
    run_dedup_report(update_scores=args.update)
