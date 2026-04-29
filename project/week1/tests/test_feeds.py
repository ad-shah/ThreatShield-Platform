"""
Week 1 — Test Suite
Run with: pytest tests/ -v
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from unittest.mock import patch, MagicMock
from normalizer import normalize_indicator, detect_indicator_type, compute_risk_score


class TestTypeDetection:

    def test_ipv4_address(self):
        assert detect_indicator_type("185.220.101.45") == "ip"

    def test_ipv6_address(self):
        assert detect_indicator_type("2001:db8::1") == "ip"

    def test_md5_hash(self):
        assert detect_indicator_type("d41d8cd98f00b204e9800998ecf8427e") == "hash"

    def test_sha1_hash(self):
        assert detect_indicator_type("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "hash"

    def test_sha256_hash(self):
        assert detect_indicator_type("a" * 64) == "hash"

    def test_http_url(self):
        assert detect_indicator_type("http://malware.example.com/payload.exe") == "url"

    def test_https_url(self):
        assert detect_indicator_type("https://phish.evil.com/login") == "url"

    def test_domain(self):
        assert detect_indicator_type("malware.evil.com") == "domain"

    def test_unknown_returns_none(self):
        assert detect_indicator_type("not-valid!!") is None


class TestRiskScoring:

    def test_explicit_score_used(self):
        assert compute_risk_score({"score": 88}, "any") == 88

    def test_score_clamped_at_100(self):
        assert compute_risk_score({"score": 150}, "any") == 100

    def test_score_clamped_at_0(self):
        assert compute_risk_score({"score": -20}, "any") == 0

    def test_baseline_score(self):
        assert compute_risk_score({}, "unknown_feed") == 50

    def test_high_risk_category_increases_score(self):
        raw   = {"categories": ["ransomware"]}
        score = compute_risk_score(raw, "unknown_feed")
        assert score > 50

    def test_trusted_feed_increases_score(self):
        score_feodo = compute_risk_score({}, "feodo")
        score_other = compute_risk_score({}, "unknown_feed")
        assert score_feodo > score_other

    def test_score_never_exceeds_100(self):
        raw = {
            "categories": ["ransomware", "c2", "malware"],
            "vt_positives": 70,
            "vt_total": 70,
        }
        assert compute_risk_score(raw, "feodo") <= 100


class TestNormalizer:

    def test_valid_public_ip(self):
        raw    = {"indicator": "185.220.101.45", "categories": ["malware"]}
        result = normalize_indicator(raw, "feodo")
        assert result is not None
        assert result["indicator"] == "185.220.101.45"
        assert result["type"] == "ip"
        assert result["source"] == "feodo"
        assert 0 <= result["risk_score"] <= 100
        assert result["active"] is True
        assert result["blocked"] is False

    def test_private_ip_rejected(self):
        assert normalize_indicator({"indicator": "192.168.1.100"}, "test") is None

    def test_loopback_rejected(self):
        assert normalize_indicator({"indicator": "127.0.0.1"}, "test") is None

    def test_empty_record_rejected(self):
        assert normalize_indicator({}, "test") is None

    def test_domain_indicator(self):
        raw    = {"indicator": "evil.botnet.ru", "categories": ["botnet"]}
        result = normalize_indicator(raw, "otx")
        assert result is not None
        assert result["type"] == "domain"

    def test_hash_indicator(self):
        raw    = {"indicator": "d41d8cd98f00b204e9800998ecf8427e"}
        result = normalize_indicator(raw, "vt")
        assert result is not None
        assert result["type"] == "hash"

    def test_categories_are_lowercase(self):
        raw    = {"indicator": "1.1.1.1", "categories": ["MALWARE", "Botnet"]}
        result = normalize_indicator(raw, "test")
        for cat in result["categories"]:
            assert cat == cat.lower()


class TestFeodoFeed:

    def test_parses_correctly(self):
        from feeds.feodo import FeodoFeed
        mock_data = [{
            "ip_address": "185.220.101.1",
            "port": 8080,
            "status": "online",
            "malware": "Emotet",
            "first_seen": "2024-01-01 00:00:00",
            "country": "DE",
        }]
        with patch("requests.get") as mock_get:
            mock_get.return_value = MagicMock(
                status_code=200,
                json=lambda: mock_data,
            )
            mock_get.return_value.raise_for_status = lambda: None
            feed    = FeodoFeed()
            results = feed.fetch()

        assert len(results) == 1
        assert results[0]["indicator"] == "185.220.101.1"
        assert results[0]["score"] == 95

    def test_returns_empty_on_error(self):
        from feeds.feodo import FeodoFeed
        with patch("requests.get", side_effect=Exception("Network failure")):
            feed    = FeodoFeed()
            results = feed.fetch()
        assert results == []


class TestEmergingThreatsFeed:

    def test_parses_plaintext(self):
        from feeds.emergingthreats import EmergingThreatsFeed
        mock_text = "# Comment\n1.2.3.4\n5.6.7.8\n\n9.10.11.12"

        with patch("requests.get") as mock_get:
            mock_get.return_value = MagicMock(
                status_code=200,
                text=mock_text,
            )
            mock_get.return_value.raise_for_status = lambda: None
            feed    = EmergingThreatsFeed()
            results = feed.fetch()

        assert len(results) == 3
        assert results[0]["indicator"] == "1.2.3.4"

    def test_skips_comments(self):
        from feeds.emergingthreats import EmergingThreatsFeed
        mock_text = "# Only comments\n# Nothing else"

        with patch("requests.get") as mock_get:
            mock_get.return_value = MagicMock(status_code=200, text=mock_text)
            mock_get.return_value.raise_for_status = lambda: None
            feed    = EmergingThreatsFeed()
            results = feed.fetch()

        assert results == []
