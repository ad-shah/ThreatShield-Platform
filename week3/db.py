"""
Week 3 — MongoDB Client
Reads high risk indicators and updates block status
"""

import logging
from datetime import datetime, timezone
from typing import List

from pymongo import MongoClient, DESCENDING

log = logging.getLogger("week3.db")


class MongoStore:

    def __init__(self, uri: str = "mongodb://localhost:27017/threat_intel"):
        log.info("Connecting to MongoDB...")
        self.client     = MongoClient(uri, serverSelectionTimeoutMS=5000)
        self.db         = self.client["threat_intel"]
        self.indicators = self.db["indicators"]
        self.audit_log  = self.db["audit_log"]
        self.client.server_info()
        log.info("MongoDB connected")

    def get_high_risk(self, threshold: int = 70, limit: int = 500) -> List[dict]:
        """Get all high risk indicators above threshold."""
        return list(
            self.indicators.find(
                {
                    "risk_score": {"$gte": threshold},
                    "active":     True,
                    "blocked":    False,
                    "type":       "ip",
                },
                {"_id": 0}
            )
            .sort("risk_score", DESCENDING)
            .limit(limit)
        )

    def mark_blocked(self, indicator: str, rule_id: str):
        """Mark indicator as blocked in MongoDB."""
        self.indicators.update_one(
            {"indicator": indicator},
            {"$set": {
                "blocked":    True,
                "rule_id":    rule_id,
                "blocked_at": datetime.now(timezone.utc),
            }}
        )

    def mark_unblocked(self, indicator: str):
        """Mark indicator as unblocked in MongoDB."""
        self.indicators.update_one(
            {"indicator": indicator},
            {"$set": {
                "blocked":       False,
                "rule_id":       None,
                "rolled_back_at": datetime.now(timezone.utc),
            }}
        )

    def log_audit(self, action: str, indicator: str, details: dict):
        """Write audit log entry."""
        self.audit_log.insert_one({
            "timestamp": datetime.now(timezone.utc),
            "action":    action,
            "indicator": indicator,
            "details":   details,
        })

    def get_blocked(self) -> List[dict]:
        """Get all currently blocked indicators."""
        return list(
            self.indicators.find(
                {"blocked": True},
                {"_id": 0, "raw": 0}
            )
        )

    def get_stats(self) -> dict:
        """Get summary statistics."""
        return {
            "total":     self.indicators.count_documents({}),
            "high_risk": self.indicators.count_documents({"risk_score": {"$gte": 70}}),
            "blocked":   self.indicators.count_documents({"blocked": True}),
        }
