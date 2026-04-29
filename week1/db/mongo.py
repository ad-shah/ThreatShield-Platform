"""
Week 1 — MongoDB Data Store
"""

import logging
from datetime import datetime, timezone
from typing import List, Optional, Dict

from pymongo import MongoClient, UpdateOne, ASCENDING, DESCENDING
from pymongo.errors import BulkWriteError, ConnectionFailure

log = logging.getLogger("week1.db.mongo")


class MongoStore:

    def __init__(self, uri: str = "mongodb://localhost:27017/threat_intel"):
        log.info("Connecting to MongoDB...")
        try:
            self.client = MongoClient(uri, serverSelectionTimeoutMS=5000)
            self.client.server_info()
            log.info("MongoDB connected")
        except ConnectionFailure as e:
            log.error("Cannot connect to MongoDB: %s", e)
            log.error("Start MongoDB: sudo systemctl start mongod")
            raise

        self.db         = self.client["threat_intel"]
        self.indicators = self.db["indicators"]
        self.audit_log  = self.db["audit_log"]
        self._create_indexes()

    def _create_indexes(self):
        self.indicators.create_index(
            [("indicator", ASCENDING), ("source", ASCENDING)],
            unique=True,
            name="indicator_source_unique",
        )
        self.indicators.create_index([("risk_score", DESCENDING)], name="risk_score_idx")
        self.indicators.create_index([("type", ASCENDING)],        name="type_idx")
        self.indicators.create_index([("blocked", ASCENDING)],     name="blocked_idx")
        self.indicators.create_index([("last_seen", DESCENDING)],  name="last_seen_idx")
        log.info("MongoDB indexes created")

    def upsert_indicators(self, indicators: List[dict]) -> int:
        if not indicators:
            return 0

        operations = []
        for ind in indicators:
            match_filter = {
                "indicator": ind["indicator"],
                "source":    ind["source"],
            }
            update_doc = {
                "$set":         ind,
                "$setOnInsert": {"created_at": datetime.now(timezone.utc)},
            }
            operations.append(UpdateOne(match_filter, update_doc, upsert=True))

        try:
            result = self.indicators.bulk_write(operations, ordered=False)
            total  = result.upserted_count + result.modified_count
            return total
        except BulkWriteError as bwe:
            log.warning("Bulk write errors: %d", len(bwe.details.get("writeErrors", [])))
            return bwe.details.get("nInserted", 0) + bwe.details.get("nModified", 0)

    def get_all(self, limit: int = 1000) -> List[dict]:
        return list(
            self.indicators
            .find({}, {"_id": 0, "raw": 0})
            .sort("risk_score", DESCENDING)
            .limit(limit)
        )

    def get_high_risk(self, threshold: int = 70, limit: int = 500) -> List[dict]:
        return list(
            self.indicators
            .find(
                {"risk_score": {"$gte": threshold}, "active": True},
                {"_id": 0, "raw": 0}
            )
            .sort("risk_score", DESCENDING)
            .limit(limit)
        )

    def get_by_type(self, itype: str) -> List[dict]:
        return list(
            self.indicators
            .find({"type": itype}, {"_id": 0, "raw": 0})
            .sort("risk_score", DESCENDING)
        )

    def search(self, value: str) -> Optional[dict]:
        return self.indicators.find_one({"indicator": value}, {"_id": 0})

    def get_stats(self) -> Dict:
        total     = self.indicators.count_documents({})
        high_risk = self.indicators.count_documents({"risk_score": {"$gte": 70}})
        blocked   = self.indicators.count_documents({"blocked": True})

        by_type = list(self.indicators.aggregate([
            {"$group": {"_id": "$type", "count": {"$sum": 1}}}
        ]))
        by_source = list(self.indicators.aggregate([
            {"$group": {"_id": "$source", "count": {"$sum": 1}}}
        ]))

        return {
            "total":     total,
            "high_risk": high_risk,
            "blocked":   blocked,
            "by_type":   {d["_id"]: d["count"] for d in by_type},
            "by_source": {d["_id"]: d["count"] for d in by_source},
        }

    def mark_blocked(self, indicator: str, rule_id: str):
        self.indicators.update_one(
            {"indicator": indicator},
            {"$set": {
                "blocked":    True,
                "rule_id":    rule_id,
                "blocked_at": datetime.now(timezone.utc),
            }}
        )

    def log_action(self, action: str, indicator: str, details: dict):
        self.audit_log.insert_one({
            "timestamp": datetime.now(timezone.utc),
            "action":    action,
            "indicator": indicator,
            "details":   details,
        })
