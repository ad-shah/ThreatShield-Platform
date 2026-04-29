"""
Week 3 — Rollback Manager
Saves all applied rules so SOC analysts can reverse them
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import List, Optional

log = logging.getLogger("week3.rollback")


class RollbackManager:

    def __init__(self, path: str = "logs/rollback.json"):
        self.path   = path
        self._rules = self._load()

    def _load(self) -> dict:
        if os.path.exists(self.path):
            try:
                with open(self.path) as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def _save(self):
        with open(self.path, "w") as f:
            json.dump(self._rules, f, indent=2, default=str)

    def record(self, rule_id: str, indicator: str, risk_score: int):
        """Record a new block rule."""
        self._rules[rule_id] = {
            "rule_id":     rule_id,
            "indicator":   indicator,
            "risk_score":  risk_score,
            "applied_at":  datetime.now(timezone.utc).isoformat(),
            "rolled_back": False,
        }
        self._save()
        log.info("Recorded rule %s for %s", rule_id, indicator)

    def mark_rolled_back(self, rule_id: str):
        """Mark a rule as rolled back."""
        if rule_id in self._rules:
            self._rules[rule_id]["rolled_back"]    = True
            self._rules[rule_id]["rolled_back_at"] = datetime.now(timezone.utc).isoformat()
            self._save()
            log.info("Rule %s marked as rolled back", rule_id)

    def get_active_rules(self) -> List[dict]:
        """Return all rules that have not been rolled back."""
        return [
            r for r in self._rules.values()
            if not r.get("rolled_back")
        ]

    def get_all_rules(self) -> List[dict]:
        """Return all rules including rolled back ones."""
        return list(self._rules.values())

    def get_rule(self, rule_id: str) -> Optional[dict]:
        """Get a specific rule by ID."""
        return self._rules.get(rule_id)

    def print_active_rules(self):
        """Print all active rules to console."""
        active = self.get_active_rules()
        if not active:
            print("No active blocked rules.")
            return
        print(f"\n{'RULE_ID':<12} {'INDICATOR':<22} {'SCORE':<8} {'APPLIED_AT'}")
        print("-" * 70)
        for r in active:
            print(
                f"{r['rule_id']:<12} "
                f"{r['indicator']:<22} "
                f"{r['risk_score']:<8} "
                f"{r.get('applied_at','—')}"
            )
