"""
Week 4 — Email Alerting System
Sends email alerts when critical threats are detected
"""

import os
import sys
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone
from typing import List

from dotenv import load_dotenv
load_dotenv()

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "week1"))

log = logging.getLogger("week4.alerting")

SMTP_HOST   = os.getenv("SMTP_HOST",   "smtp.gmail.com")
SMTP_PORT   = int(os.getenv("SMTP_PORT", 587))
SMTP_USER   = os.getenv("SMTP_USER",   "")
SMTP_PASS   = os.getenv("SMTP_PASS",   "")
ALERT_EMAIL = os.getenv("ALERT_EMAIL", "")


def send_email(subject: str, body: str) -> bool:
    """Send email alert to SOC team."""
    if not all([SMTP_USER, SMTP_PASS, ALERT_EMAIL]):
        log.warning("Email not configured — skipping alert")
        log.warning("Set SMTP_USER, SMTP_PASS, ALERT_EMAIL in .env")
        return False

    try:
        msg = MIMEMultipart()
        msg["From"]    = SMTP_USER
        msg["To"]      = ALERT_EMAIL
        msg["Subject"] = subject

        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)

        log.info("Alert email sent to %s", ALERT_EMAIL)
        return True

    except Exception as e:
        log.error("Failed to send email: %s", e)
        return False


def send_critical_alert(indicators: List[dict]) -> bool:
    """Send alert for critical threat indicators."""
    if not indicators:
        return False

    subject = f"[TIP ALERT] {len(indicators)} Critical Threats Detected"

    lines = []
    lines.append("THREAT INTELLIGENCE PLATFORM ALERT")
    lines.append("=" * 50)
    lines.append(f"Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC")
    lines.append(f"Critical threats detected: {len(indicators)}")
    lines.append("")
    lines.append("TOP CRITICAL INDICATORS:")
    lines.append("-" * 50)

    for ind in indicators[:10]:
        lines.append(
            f"IP: {ind.get('indicator','?'):<20} "
            f"Score: {ind.get('risk_score','?'):<5} "
            f"Source: {ind.get('source','?')}"
        )

    lines.append("")
    lines.append("Action: Log into SOC Dashboard to review")
    lines.append("Dashboard: http://localhost:8000")
    lines.append("")
    lines.append("This is an automated alert from TIP.")

    body = "\n".join(lines)
    return send_email(subject, body)


def send_block_alert(indicator: str, risk_score: int, rule_id: str) -> bool:
    """Send alert when an IP is blocked."""
    subject = f"[TIP] IP Blocked: {indicator}"

    body = f"""
THREAT INTELLIGENCE PLATFORM
IP BLOCKED NOTIFICATION
{'=' * 40}
Time      : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC
IP Address: {indicator}
Risk Score: {risk_score}
Rule ID   : {rule_id}
Action    : DROP rule added to iptables

To rollback this block:
python week3/main.py --rollback {indicator}

Or use the SOC Dashboard:
http://localhost:8000
"""
    return send_email(subject, body)


def check_and_alert(mongo_uri: str = "mongodb://localhost:27017/threat_intel"):
    """Check for critical threats and send alerts."""
    from db.mongo import MongoStore
    store = MongoStore(mongo_uri)

    critical = store.get_high_risk(threshold=90, limit=50)

    if critical:
        log.info("Found %d critical threats — sending alert", len(critical))
        send_critical_alert(critical)
    else:
        log.info("No critical threats found — no alert needed")

    return len(critical)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    mongo_uri = os.getenv(
        "MONGO_URI",
        "mongodb://localhost:27017/threat_intel"
    )
    count = check_and_alert(mongo_uri)
    print(f"Critical threats found: {count}")
