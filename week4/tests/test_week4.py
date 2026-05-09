"""
Week 4 — Test Suite
Run with: pytest tests/ -v
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from api import app

client = TestClient(app)


class TestHealthEndpoint:

    def test_health_returns_ok(self):
        r = client.get("/api/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_health_has_timestamp(self):
        r = client.get("/api/health")
        assert "timestamp" in r.json()

    def test_health_has_version(self):
        r = client.get("/api/health")
        assert r.json()["version"] == "1.0.0"


class TestStatsEndpoint:

    def test_stats_returns_200(self):
        r = client.get("/api/stats")
        assert r.status_code == 200

    def test_stats_has_required_fields(self):
        r    = client.get("/api/stats")
        data = r.json()
        assert "total"     in data
        assert "high_risk" in data
        assert "blocked"   in data
        assert "critical"  in data

    def test_stats_values_are_integers(self):
        r    = client.get("/api/stats")
        data = r.json()
        assert isinstance(data["total"],     int)
        assert isinstance(data["high_risk"], int)
        assert isinstance(data["blocked"],   int)


class TestIndicatorsEndpoint:

    def test_indicators_returns_200(self):
        r = client.get("/api/indicators")
        assert r.status_code == 200

    def test_indicators_has_data_and_total(self):
        r    = client.get("/api/indicators")
        data = r.json()
        assert "data"  in data
        assert "total" in data

    def test_indicators_limit_works(self):
        r    = client.get("/api/indicators?limit=5")
        data = r.json()
        assert len(data["data"]) <= 5

    def test_indicators_type_filter(self):
        r    = client.get("/api/indicators?type=ip")
        data = r.json()
        for ind in data["data"]:
            assert ind["type"] == "ip"


class TestAuditEndpoint:

    def test_audit_returns_200(self):
        r = client.get("/api/audit")
        assert r.status_code == 200

    def test_audit_has_data(self):
        r    = client.get("/api/audit")
        data = r.json()
        assert "data" in data


class TestTopThreatsEndpoint:

    def test_top_threats_returns_200(self):
        r = client.get("/api/top-threats")
        assert r.status_code == 200

    def test_top_threats_has_data(self):
        r    = client.get("/api/top-threats")
        data = r.json()
        assert "data" in data

    def test_top_threats_limit(self):
        r    = client.get("/api/top-threats?limit=5")
        data = r.json()
        assert len(data["data"]) <= 5


class TestRollbackEndpoint:

    def test_rollback_not_found(self):
        r = client.post("/api/rollback/999.999.999.999")
        assert r.status_code == 404

    def test_rollback_not_blocked(self):
        r = client.get("/api/indicators?type=ip&limit=1")
        indicators = r.json().get("data", [])
        if indicators:
            ind = indicators[0]
            if not ind.get("blocked"):
                r2 = client.post(
                    f"/api/rollback/{ind['indicator']}"
                )
                assert r2.status_code == 400


class TestAlerting:

    def test_send_email_no_config(self):
        from alerting import send_email
        result = send_email("Test", "Test body")
        assert result is False

    def test_send_critical_alert_empty(self):
        from alerting import send_critical_alert
        result = send_critical_alert([])
        assert result is False

    def test_send_block_alert_no_config(self):
        from alerting import send_block_alert
        result = send_block_alert("1.2.3.4", 95, "test123")
        assert result is False
