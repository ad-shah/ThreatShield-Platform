"""
Week 2 — Elasticsearch Client
"""

import logging
from datetime import datetime, timezone
from typing import List, Dict

log = logging.getLogger("week2.es_client")

INDEX_PATTERN = "threat-indicators"


class ESClient:

    def __init__(self, host: str = "http://localhost:9200"):
        try:
            from elasticsearch import Elasticsearch
        except ImportError:
            raise ImportError("Run: pip install elasticsearch==8.13.0")

        self.es    = Elasticsearch(host)
        self._host = host
        self._verify_connection()
        self._create_index_template()

    def _verify_connection(self):
        info = self.es.info()
        log.info("Connected to Elasticsearch %s", info["version"]["number"])

    def _create_index_template(self):
        template_body = {
            "index_patterns": [f"{INDEX_PATTERN}-*"],
            "template": {
                "mappings": {
                    "properties": {
                        "indicator":      {"type": "keyword"},
                        "indicator_type": {"type": "keyword"},
                        "feed_source":    {"type": "keyword"},
                        "risk_score":     {"type": "integer"},
                        "risk_level":     {"type": "keyword"},
                        "categories":     {"type": "keyword"},
                        "geo_country":    {"type": "keyword"},
                        "is_blocked":     {"type": "boolean"},
                        "description":    {"type": "text"},
                        "@timestamp":     {"type": "date"},
                    }
                }
            }
        }
        try:
            self.es.indices.put_index_template(
                name="tip-indicators-template",
                body=template_body,
            )
            log.info("Index template created")
        except Exception as e:
            log.warning("Template may already exist: %s", e)

    def bulk_index(self, documents: List[dict]) -> int:
        from elasticsearch.helpers import bulk, BulkIndexError

        today      = datetime.now(timezone.utc).strftime("%Y.%m.%d")
        index_name = f"{INDEX_PATTERN}-{today}"

        actions = []
        for doc in documents:
            doc_id = f"{doc.get('indicator','')}_{doc.get('feed_source','')}"
            actions.append({
                "_index":  index_name,
                "_id":     doc_id,
                "_source": doc,
            })

        try:
            success, failed = bulk(self.es, actions, raise_on_error=False)
            if failed:
                log.warning("%d documents failed", len(failed))
            log.info("Bulk indexed %d documents into %s", success, index_name)
            return success
        except BulkIndexError as e:
            log.error("Bulk index error: %d failures", len(e.errors))
            return 0
        except Exception as e:
            log.error("Unexpected bulk error: %s", e)
            return 0

    def get_risk_stats(self) -> Dict:
        try:
            resp = self.es.search(
                index=f"{INDEX_PATTERN}-*",
                size=0,
                aggs={
                    "by_risk_level": {"terms": {"field": "risk_level"}},
                    "by_type":       {"terms": {"field": "indicator_type"}},
                    "by_source":     {"terms": {"field": "feed_source"}},
                    "avg_risk_score":{"avg":   {"field": "risk_score"}},
                }
            )
            aggs = resp["aggregations"]
            return {
                "by_risk_level":  {b["key"]: b["doc_count"] for b in aggs["by_risk_level"]["buckets"]},
                "by_type":        {b["key"]: b["doc_count"] for b in aggs["by_type"]["buckets"]},
                "by_source":      {b["key"]: b["doc_count"] for b in aggs["by_source"]["buckets"]},
                "avg_risk_score": round(aggs["avg_risk_score"]["value"] or 0, 1),
                "total":          resp["hits"]["total"]["value"],
            }
        except Exception as e:
            log.error("Stats error: %s", e)
            return {}

    def health(self) -> str:
        try:
            return self.es.cluster.health()["status"]
        except Exception:
            return "unreachable"
