"""
Week 4 — FastAPI SOC Dashboard Backend
"""

import os
import sys
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from pymongo import MongoClient, DESCENDING
from dotenv import load_dotenv

load_dotenv()

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "week1"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("week4.api")

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/threat_intel")

client     = MongoClient(MONGO_URI)
db         = client["threat_intel"]
indicators = db["indicators"]
audit_log  = db["audit_log"]

app = FastAPI(
    title="Threat Intelligence Platform API",
    version="1.0.0",
    description="TIP SOC Dashboard API — Week 4"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="static"), name="static")


# ── Helper ────────────────────────────────────────────────

def clean(doc: dict) -> dict:
    doc.pop("_id", None)
    doc.pop("raw", None)
    for k, v in doc.items():
        if isinstance(v, datetime):
            doc[k] = v.isoformat()
    return doc


# ── Routes ────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def dashboard():
    return FileResponse("static/index.html")


@app.get("/api/stats")
def get_stats():
    total     = indicators.count_documents({})
    high_risk = indicators.count_documents({"risk_score": {"$gte": 70}})
    blocked   = indicators.count_documents({"blocked": True})
    critical  = indicators.count_documents({"risk_score": {"$gte": 90}})

    by_type = list(indicators.aggregate([
        {"$group": {"_id": "$type", "count": {"$sum": 1}}}
    ]))
    by_source = list(indicators.aggregate([
        {"$group": {"_id": "$source", "count": {"$sum": 1}}}
    ]))

    return {
        "total":     total,
        "high_risk": high_risk,
        "blocked":   blocked,
        "critical":  critical,
        "by_type":   {d["_id"]: d["count"] for d in by_type},
        "by_source": {d["_id"]: d["count"] for d in by_source},
    }


@app.get("/api/indicators")
def list_indicators(
    type:      Optional[str] = None,
    min_score: int = 0,
    blocked:   Optional[bool] = None,
    limit:     int = 100,
    skip:      int = 0,
):
    query = {}
    if type:
        query["type"] = type
    if min_score:
        query["risk_score"] = {"$gte": min_score}
    if blocked is not None:
        query["blocked"] = blocked

    docs = list(
        indicators
        .find(query, {"_id": 0, "raw": 0})
        .sort("risk_score", DESCENDING)
        .skip(skip)
        .limit(limit)
    )
    total = indicators.count_documents(query)
    return {"data": [clean(d) for d in docs], "total": total}


@app.get("/api/indicators/{indicator_value}")
def get_indicator(indicator_value: str):
    doc = indicators.find_one(
        {"indicator": indicator_value},
        {"_id": 0}
    )
    if not doc:
        raise HTTPException(status_code=404, detail="Indicator not found")
    return clean(doc)


@app.get("/api/top-threats")
def top_threats(limit: int = 10):
    docs = list(
        indicators
        .find({"active": True}, {"_id": 0, "raw": 0})
        .sort("risk_score", DESCENDING)
        .limit(limit)
    )
    return {"data": [clean(d) for d in docs]}


@app.get("/api/audit")
def get_audit(limit: int = 100):
    docs = list(
        audit_log
        .find({}, {"_id": 0})
        .sort("timestamp", DESCENDING)
        .limit(limit)
    )
    return {"data": [clean(d) for d in docs]}


@app.post("/api/rollback/{indicator}")
def rollback_block(indicator: str):
    doc = indicators.find_one({"indicator": indicator})
    if not doc:
        raise HTTPException(status_code=404, detail="Indicator not found")
    if not doc.get("blocked"):
        raise HTTPException(status_code=400, detail="Indicator is not blocked")

    indicators.update_one(
        {"indicator": indicator},
        {"$set": {
            "blocked":        False,
            "rule_id":        None,
            "rolled_back_at": datetime.now(timezone.utc),
        }}
    )
    audit_log.insert_one({
        "timestamp": datetime.now(timezone.utc),
        "action":    "ROLLBACK",
        "indicator": indicator,
        "details":   {"performed_by": "soc_dashboard"},
    })
    return {
        "status":  "ok",
        "message": f"Block on {indicator} reversed successfully"
    }


@app.get("/api/blocked")
def get_blocked():
    docs = list(
        indicators
        .find({"blocked": True}, {"_id": 0, "raw": 0})
        .sort("blocked_at", DESCENDING)
    )
    return {"data": [clean(d) for d in docs], "total": len(docs)}


@app.get("/api/health")
def health():
    return {
        "status":    "ok",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version":   "1.0.0"
    }
