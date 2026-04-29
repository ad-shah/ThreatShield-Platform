"""
Week 2 — Schema Validator
Validates all MongoDB documents against expected schema
"""

import os
import sys
import logging
import argparse

log = logging.getLogger("week2.schema_validator")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "week1"))

MONGO_URI   = os.getenv("MONGO_URI", "mongodb://localhost:27017/threat_intel")
REQUIRED    = ["indicator", "type", "source", "risk_score", "active"]
VALID_TYPES = {"ip", "domain", "url", "hash"}


def valid_score(score) -> bool:
    return isinstance(score, int) and 0 <= score <= 100


def validate_all(fix: bool = False):
    from db.mongo import MongoStore
    store = MongoStore(MONGO_URI)

    log.info("Loading all indicators...")
    docs   = list(store.indicators.find({}))
    log.info("Validating %d documents...", len(docs))

    errors = []
    for doc in docs:
        doc_errors = []
        indicator  = doc.get("indicator", "<missing>")

        for field in REQUIRED:
            if field not in doc:
                doc_errors.append(f"Missing field: '{field}'")

        if doc.get("type") not in VALID_TYPES:
            doc_errors.append(f"Invalid type: '{doc.get('type')}'")

        if not valid_score(doc.get("risk_score")):
            doc_errors.append(f"Invalid risk_score: {doc.get('risk_score')}")

        if not str(doc.get("indicator", "")).strip():
            doc_errors.append("Empty indicator value")

        if doc_errors:
            errors.append({
                "indicator": indicator,
                "id":        doc["_id"],
                "errors":    doc_errors
            })

    print("\n" + "=" * 60)
    print("  SCHEMA VALIDATION REPORT")
    print("=" * 60)
    print(f"  Documents checked : {len(docs)}")
    print(f"  Documents valid   : {len(docs) - len(errors)}")
    print(f"  Documents invalid : {len(errors)}")

    if errors:
        print("\n  ERRORS FOUND:")
        for err in errors[:20]:
            print(f"\n  Indicator: {err['indicator']}")
            for e in err["errors"]:
                print(f"    x {e}")

        if fix:
            print(f"\n  Fixing {len(errors)} documents...")
            fixed = 0
            for err in errors:
                updates = {}
                for msg in err["errors"]:
                    if "risk_score" in msg:
                        updates["risk_score"] = 50
                    if "Missing field: 'active'" in msg:
                        updates["active"] = True
                if updates:
                    store.indicators.update_one(
                        {"_id": err["id"]},
                        {"$set": updates}
                    )
                    fixed += 1
            print(f"  Fixed {fixed} documents")
    else:
        print("\n  All documents are valid!")
    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--fix", action="store_true")
    args = parser.parse_args()
    validate_all(fix=args.fix)
