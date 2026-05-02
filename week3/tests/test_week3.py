"""
Week 3 — Test Suite
Run with: pytest tests/ -v
"""

import sys
import os
import json
import tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from unittest.mock import patch, MagicMock, call

from enforcer import IPTablesEnforcer
from rollback  import RollbackManager


class TestIPTablesEnforcer:

    def test_block_ip_dry_run(self):
        enforcer = IPTablesEnforcer()
        enforcer.block_ip("185.220.101.45", "test123", dry_run=True)

    def test_unblock_ip_dry_run(self):
        enforcer = IPTablesEnforcer()
        enforcer.unblock_ip("185.220.101.45", "test123", dry_run=True)

    def test_setup_chain_dry_run(self):
        enforcer = IPTablesEnforcer()
        enforcer.setup_chain(dry_run=True)

    def test_flush_chain_dry_run(self):
        enforcer = IPTablesEnforcer()
        enforcer.flush_chain(dry_run=True)

    def test_block_ip_calls_iptables(self):
        enforcer = IPTablesEnforcer()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            enforcer.block_ip("1.2.3.4", "abc123", dry_run=False)
            assert mock_run.called

    def test_block_ip_raises_on_failure(self):
        enforcer = IPTablesEnforcer()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="error")
            with pytest.raises(RuntimeError):
                enforcer.block_ip("1.2.3.4", "abc123", dry_run=False)


class TestRollbackManager:

    def test_record_and_retrieve(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            path = f.name

        rb = RollbackManager(path)
        rb.record("rule001", "185.220.101.1", 95)

        rules = rb.get_active_rules()
        assert len(rules) == 1
        assert rules[0]["indicator"] == "185.220.101.1"
        assert rules[0]["rule_id"]   == "rule001"
        assert rules[0]["risk_score"] == 95

    def test_mark_rolled_back(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            path = f.name

        rb = RollbackManager(path)
        rb.record("rule002", "1.2.3.4", 80)
        rb.mark_rolled_back("rule002")

        active = rb.get_active_rules()
        assert len(active) == 0

        all_rules = rb.get_all_rules()
        assert len(all_rules) == 1
        assert all_rules[0]["rolled_back"] is True

    def test_get_rule_by_id(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            path = f.name

        rb = RollbackManager(path)
        rb.record("rule003", "5.6.7.8", 75)
        rule = rb.get_rule("rule003")

        assert rule is not None
        assert rule["indicator"] == "5.6.7.8"

    def test_multiple_rules(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            path = f.name

        rb = RollbackManager(path)
        rb.record("r001", "1.1.1.1", 90)
        rb.record("r002", "2.2.2.2", 85)
        rb.record("r003", "3.3.3.3", 80)

        assert len(rb.get_active_rules()) == 3
        rb.mark_rolled_back("r001")
        assert len(rb.get_active_rules()) == 2

    def test_empty_rules(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            path = f.name

        rb = RollbackManager(path)
        assert rb.get_active_rules() == []
        assert rb.get_rule("nonexistent") is None
