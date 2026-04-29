"""
Week 3 — iptables Enforcer
Dynamically blocks malicious IPs using iptables
"""

import logging
import subprocess
import shlex
from typing import List

log = logging.getLogger("week3.enforcer")

CHAIN_NAME = "TIP_BLOCKLIST"


class IPTablesEnforcer:

    def _run(self, cmd: str, dry_run: bool = False) -> bool:
        if dry_run:
            log.info("[DRY-RUN] Would execute: %s", cmd)
            return True
        try:
            result = subprocess.run(
                shlex.split(cmd),
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                log.warning("iptables stderr: %s", result.stderr.strip())
                return False
            return True
        except FileNotFoundError:
            log.error("iptables not found — need root/sudo access")
            return False
        except subprocess.TimeoutExpired:
            log.error("iptables command timed out: %s", cmd)
            return False
        except Exception as e:
            log.error("iptables error: %s", e)
            return False

    def setup_chain(self, dry_run: bool = False):
        """Create custom chain and link to INPUT."""
        self._run(f"iptables -N {CHAIN_NAME}", dry_run)
        self._run(f"iptables -I INPUT 1 -j {CHAIN_NAME}", dry_run)
        log.info("iptables chain %s ready (dry_run=%s)", CHAIN_NAME, dry_run)

    def block_ip(self, ip: str, rule_id: str, dry_run: bool = False):
        """Add DROP rule for malicious IP."""
        comment = f"TIP-{rule_id}"
        cmd = (
            f"iptables -A {CHAIN_NAME} -s {ip} -j DROP "
            f"-m comment --comment {comment}"
        )
        success = self._run(cmd, dry_run)
        if not success:
            raise RuntimeError(f"Failed to block {ip}")
        log.info(
            "%sBLOCKED %s (rule=%s)",
            "[DRY] " if dry_run else "",
            ip,
            rule_id,
        )

    def unblock_ip(self, ip: str, rule_id: str, dry_run: bool = False):
        """Remove DROP rule for IP."""
        comment = f"TIP-{rule_id}"
        cmd = (
            f"iptables -D {CHAIN_NAME} -s {ip} -j DROP "
            f"-m comment --comment {comment}"
        )
        success = self._run(cmd, dry_run)
        if not success:
            log.warning("Could not remove rule for %s", ip)
        else:
            log.info(
                "%sUNBLOCKED %s (rule=%s)",
                "[DRY] " if dry_run else "",
                ip,
                rule_id,
            )

    def list_blocked(self) -> List[str]:
        """List all rules in TIP_BLOCKLIST chain."""
        try:
            result = subprocess.run(
                ["iptables", "-L", CHAIN_NAME, "-n", "--line-numbers"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.stdout.splitlines()
        except Exception as e:
            log.error("Cannot list iptables rules: %s", e)
            return []

    def flush_chain(self, dry_run: bool = False):
        """Remove all rules from custom chain."""
        self._run(f"iptables -F {CHAIN_NAME}", dry_run)
        log.info("Flushed %s chain", CHAIN_NAME)

    def chain_exists(self) -> bool:
        """Check if TIP_BLOCKLIST chain exists."""
        try:
            result = subprocess.run(
                ["iptables", "-L", CHAIN_NAME, "-n"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except Exception:
            return False
