"""
Week 3 — Dynamic Policy Enforcer Main Daemon
Monitors high risk indicators and blocks them via iptables
"""

import os
import sys
import logging
import schedule
import time
import uuid
import argparse
from datetime import datetime

from dotenv import load_dotenv
load_dotenv()

# Add week1 to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "week1"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [%(levelname)-8s]  %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("logs/enforcer.log"),
    ],
)
log = logging.getLogger("week3.main")

MONGO_URI       = os.getenv("MONGO_URI", "mongodb://localhost:27017/threat_intel")
RISK_THRESHOLD  = int(os.getenv("RISK_THRESHOLD", 70))
DRY_RUN         = os.getenv("DRY_RUN", "true").lower() in ("true", "1", "yes")
CHECK_INTERVAL  = int(os.getenv("CHECK_INTERVAL_SECONDS", 120))

from enforcer import IPTablesEnforcer
from rollback  import RollbackManager
from db        import MongoStore


def enforcement_cycle(store, enforcer, rollback, dry_run=True):
    log.info("=" * 60)
    log.info("Enforcement cycle at %s (DRY_RUN=%s)",
             datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), dry_run)
    log.info("=" * 60)

    high_risk = store.get_high_risk(threshold=RISK_THRESHOLD)
    log.info("Found %d high risk IPs (score >= %d)", len(high_risk), RISK_THRESHOLD)

    if not high_risk:
        log.info("No new IPs to block")
        return

    blocked_count = 0
    for ind in high_risk:
        indicator  = ind["indicator"]
        risk_score = ind.get("risk_score", 0)

        # Generate unique rule ID
        rule_id = str(uuid.uuid4())[:8]

        try:
            # Block the IP
            enforcer.block_ip(indicator, rule_id, dry_run=dry_run)

            # Record in rollback manager
            rollback.record(rule_id, indicator, risk_score)

            # Update MongoDB
            store.mark_blocked(indicator, rule_id)

            # Write audit log
            store.log_audit("BLOCK", indicator, {
                "rule_id":    rule_id,
                "risk_score": risk_score,
                "source":     ind.get("source"),
                "dry_run":    dry_run,
            })

            blocked_count += 1
            log.info(
                "%sBLOCKED %-20s score=%-4d rule=%s",
                "[DRY] " if dry_run else "",
                indicator,
                risk_score,
                rule_id,
            )

        except Exception as e:
            log.error("Failed to block %s: %s", indicator, e)

    log.info("Cycle complete — %d IPs %sblocked",
             blocked_count, "dry-" if dry_run else "")

    stats = store.get_stats()
    log.info("MongoDB stats: total=%d high_risk=%d blocked=%d",
             stats["total"], stats["high_risk"], stats["blocked"])


def rollback_ip(store, enforcer, rollback, indicator, dry_run=True):
    """Rollback a specific blocked IP."""
    rules = rollback.get_active_rules()
    match = next((r for r in rules if r["indicator"] == indicator), None)

    if not match:
        log.error("No active rule found for %s", indicator)
        return False

    rule_id = match["rule_id"]

    try:
        enforcer.unblock_ip(indicator, rule_id, dry_run=dry_run)
        rollback.mark_rolled_back(rule_id)
        store.mark_unblocked(indicator)
        store.log_audit("ROLLBACK", indicator, {
            "rule_id":  rule_id,
            "dry_run":  dry_run,
        })
        log.info("%sROLLBACK successful for %s",
                 "[DRY] " if dry_run else "", indicator)
        return True

    except Exception as e:
        log.error("Rollback failed for %s: %s", indicator, e)
        return False


def main():
    parser = argparse.ArgumentParser(description="Week 3 — Policy Enforcer")
    parser.add_argument("--dry-run",   action="store_true", default=True,
                        help="Simulate without applying real iptables rules")
    parser.add_argument("--live",      action="store_true",
                        help="Apply real iptables rules (needs sudo)")
    parser.add_argument("--loop",      action="store_true",
                        help="Run continuously")
    parser.add_argument("--rollback",  metavar="IP",
                        help="Rollback block on specific IP")
    parser.add_argument("--list",      action="store_true",
                        help="List all active blocked rules")
    parser.add_argument("--stats",     action="store_true",
                        help="Show MongoDB stats")
    args = parser.parse_args()

    # Live mode overrides dry-run
    dry_run = not args.live

    store    = MongoStore(MONGO_URI)
    enforcer = IPTablesEnforcer()
    rollback = RollbackManager("logs/rollback.json")

    # Show stats
    if args.stats:
        stats = store.get_stats()
        print(f"\nMongoDB Stats:")
        print(f"  Total indicators : {stats['total']}")
        print(f"  High risk (>=70) : {stats['high_risk']}")
        print(f"  Blocked          : {stats['blocked']}")
        return

    # List active rules
    if args.list:
        rollback.print_active_rules()
        return

    # Rollback specific IP
    if args.rollback:
        rollback_ip(store, enforcer, rollback, args.rollback, dry_run=dry_run)
        return

    # Setup iptables chain
    enforcer.setup_chain(dry_run=dry_run)

    if args.loop:
        log.info("Loop mode: checking every %d seconds", CHECK_INTERVAL)
        enforcement_cycle(store, enforcer, rollback, dry_run=dry_run)
        schedule.every(CHECK_INTERVAL).seconds.do(
            enforcement_cycle,
            store=store,
            enforcer=enforcer,
            rollback=rollback,
            dry_run=dry_run,
        )
        while True:
            schedule.run_pending()
            time.sleep(10)
    else:
        enforcement_cycle(store, enforcer, rollback, dry_run=dry_run)


if __name__ == "__main__":
    main()

