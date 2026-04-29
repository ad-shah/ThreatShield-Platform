"""
Week 2 — Test Suite
Run with: pytest tests/ -v
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

from siem_exporter import prepare_for_es, add_risk_level


class TestRiskLevel:

    def test_score_90_plus_is_critical(self):
        assert add_risk_level({"risk_score": 90})["risk_level"] == "CRITICAL"
        assert add_risk_level({"risk_score": 100})["risk_level"] == "CRITICAL"

    def test_score_70_to_89_is_high(self):
        assert add_risk_level({"risk_score": 70})["risk_level"] == "HIGH"
        assert add_risk_level({"risk_score": 89})["risk_level"] == "HIGH"

    def test_score_50_to_69_is_medium(self):
        assert add_risk_level({"risk_score": 50})["risk_level"] == "MEDIUM"
        assert add_risk_level({"risk_score": 69})["risk_level"] == "MEDIUM"

    def test_score_below_50_is_low(self):
        assert add_risk_level({"risk_score": 0})["risk_level"] == "LOW"
        assert add_risk_level({"risk_score": 49})["risk_level"] == "LOW"

    def test_no_score_defaults_to_low(self):
        assert add_risk_level({})["risk_level"] == "LOW"


class TestPrepareForES:

    def _make_doc(self, **kwargs):
        base = {
            "indicator":  "185.220.101.1",
            "type":       "ip",
            "source":     "feodo",
            "risk_score": 95,
            "blocked":    False,
            "active":     True,
            "last_seen":  datetime.now(timezone.utc),
            "raw":        {"original": "data"},
        }
        base.update(kwargs)
        return base

    def test_type_renamed(self):
        doc = prepare_for_es(self._make_doc())
        assert "indicator_type" in doc
        assert "type" not in doc

    def test_source_renamed(self):
        doc = prepare_for_es(self._make_doc())
        assert "feed_source" in doc
        assert "source" not in doc

    def test_blocked_renamed(self):
        doc = prepare_for_es(self._make_doc(blocked=True))
        assert "is_blocked" in doc
        assert doc["is_blocked"] is True

    def test_raw_removed(self):
        doc = prepare_for_es(self._make_doc())
        assert "raw" not in doc

    def test_timestamp_set(self):
        ts  = datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        doc = prepare_for_es(self._make_doc(last_seen=ts))
        assert "@timestamp" in doc
        assert "2024-06-01" in doc["@timestamp"]

    def test_risk_level_added(self):
        doc = prepare_for_es(self._make_doc(risk_score=95))
        assert doc.get("risk_level") == "CRITICAL"

    def test_indicator_preserved(self):
        doc = prepare_for_es(self._make_doc())
        assert doc["indicator"] == "185.220.101.1"


class TestSchemaValidator:

    def test_valid_score(self):
        from normalization.schema_validator import valid_score
        assert valid_score(0)   is True
        assert valid_score(50)  is True
        assert valid_score(100) is True

    def test_invalid_scores(self):
        from normalization.schema_validator import valid_score
        assert valid_score(-1)   is False
        assert valid_score(101)  is False
        assert valid_score(None) is False
        assert valid_score("50") is False


class TestEnrichment:

    def test_successful_enrichment(self):
        from enrichment import enrich_single_ip
        mock_response = {
            "status":      "success",
            "country":     "Germany",
            "countryCode": "DE",
            "city":        "Frankfurt",
            "isp":         "Hetzner",
            "org":         "Hetzner",
            "as":          "AS24940 Hetzner",
            "query":       "5.9.0.1",
        }
        with patch("requests.get") as mock_get:
            mock_get.return_value = MagicMock(
                status_code=200,
                json=lambda: mock_response,
            )
            mock_get.return_value.raise_for_status = lambda: None
            result = enrich_single_ip("5.9.0.1")

        assert result is not None
        assert result["geo_country"] == "Germany"
        assert result["geo_country_code"] == "DE"

    def test_failed_returns_none(self):
        from enrichment import enrich_single_ip
        mock_response = {"status": "fail", "message": "private range"}
        with patch("requests.get") as mock_get:
            mock_get.return_value = MagicMock(
                status_code=200,
                json=lambda: mock_response,
            )
            mock_get.return_value.raise_for_status = lambda: None
            result = enrich_single_ip("192.168.1.1")
        assert result is None

    def test_network_error_returns_none(self):
        from enrichment import enrich_single_ip
        with patch("requests.get", side_effect=Exception("Network error")):
            result = enrich_single_ip("8.8.8.8")
        assert result is None
