import ipaddress
import logging
import re
from datetime import datetime, timezone
from typing import Optional

import validators

log = logging.getLogger("week1.normalizer")

VALID_TYPES = {"ip", "domain", "url", "hash"}

HIGH_RISK_CATEGORIES = {
    "malware", "botnet", "ransomware", "c2", "phishing",
    "exploit", "apt", "trojan", "backdoor", "cryptominer",
    "ddos_attack", "sql_injection", "web_app_attack",
}

TRUSTED_FEEDS = {"feodo", "emergingthreats"}


def detect_indicator_type(value: str) -> Optional[str]:
    value = value.strip()

    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass

    if re.fullmatch(r"[0-9a-fA-F]{32}", value):
        return "hash"
    if re.fullmatch(r"[0-9a-fA-F]{40}", value):
        return "hash"
    if re.fullmatch(r"[0-9a-fA-F]{64}", value):
        return "hash"

    if value.startswith("http://") or value.startswith("https://"):
        return "url"

    if validators.domain(value):
        return "domain"

    return None


def compute_risk_score(raw: dict, feed_name: str) -> int:
    if "score" in raw:
        try:
            provided = int(raw["score"])
            return max(0, min(100, provided))
        except (ValueError, TypeError):
            pass

    score = 50

    raw_cats = raw.get("categories", [])
    categories = {str(c).lower() for c in raw_cats}

    if categories & HIGH_RISK_CATEGORIES:
        score += 25

    if feed_name.lower() in TRUSTED_FEEDS:
        score += 15

    vt_pos   = raw.get("vt_positives", 0)
    vt_total = raw.get("vt_total", 0)
    if vt_total > 0:
        ratio = vt_pos / vt_total
        score += int(ratio * 30)

    return max(0, min(100, score))


def normalize_indicator(raw: dict, feed_name: str) -> Optional[dict]:
    value = (
        raw.get("indicator") or
        raw.get("value") or
        raw.get("ip") or
        raw.get("ip_address") or
        raw.get("ipAddress") or
        raw.get("domain") or
        raw.get("url") or
        ""
    )
    value = str(value).strip()

    if not value:
        return None

    raw_type = raw.get("type", "")
    itype = raw_type if raw_type in VALID_TYPES else detect_indicator_type(value)

    if itype not in VALID_TYPES:
        return None

    if itype == "ip":
        try:
            addr = ipaddress.ip_address(value)
            if addr.is_private:
                return None
            if addr.is_loopback:
                return None
            if addr.is_reserved:
                return None
            if addr.is_link_local:
                return None
        except ValueError:
            return None

    risk_score = compute_risk_score(raw, feed_name)

    raw_cats = raw.get("categories", [])
    categories = list({str(c).lower() for c in raw_cats if c})

    now = datetime.now(timezone.utc)

    return {
        "indicator":      value,
        "type":           itype,
        "source":         feed_name,
        "risk_score":     risk_score,
        "categories":     categories,
        "description":    raw.get("description", ""),
        "tags":           list(raw.get("tags", [])),
        "first_seen":     raw.get("first_seen") or now,
        "last_seen":      now,
        "active":         True,
        "blocked":        False,
        "rule_id":        None,
        "country":        raw.get("country"),
        "port":           raw.get("port"),
        "malware_family": raw.get("malware_family"),
        "raw":            raw,
    }
