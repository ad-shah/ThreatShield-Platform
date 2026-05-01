=======================================================
🛡️ ADVANCED THREAT INTELLIGENCE PLATFORM (TIP)
Finance & Banking Cybersecurity Internship Project
Automatically collects, analyzes & blocks cyber threats
=======================================================

---

## PROJECT OVERVIEW

Banks and financial institutions face thousands of cyber
attacks every day. Traditional firewalls use static rules
that require manual updates — taking hours or days.

This platform COMPLETELY AUTOMATES the entire process:

• Collects real threat data every 30 minutes
• Scores each threat from 0 to 100
• Blocks dangerous IPs in under 2 minutes
• Displays everything in a live SOC dashboard
• Maintains a full audit trail for PCI-DSS compliance

---

## ARCHITECTURE

Internet (OSINT Feeds)
|
v
[Week 1] Python Aggregator
Feodo | OTX | VirusTotal | AbuseIPDB | EmergingThreats
|
v
MongoDB Database (threat_intel collection)
|
*****|*****
|           |
v           v
[Week 2]    [Week 3]
ELK Stack   Policy Enforcer
Kibana      iptables DROP rules
Dashboard   Auto blocking
|           |
|___________|
|
v
[Week 4] SOC Dashboard
FastAPI + Dark UI
Rollback + Audit Log

---

## WEEK BY WEEK PROGRESS

========================================
WEEK 1 — OSINT INGESTION & MONGODB
==================================

Objective: Collect and store real threat indicators

What we did:

• Set up Linux development environment
• Connected to 5 public OSINT threat feeds
• Built Python feed connectors for each source
• Developed normalizer to clean and score raw data
• Designed MongoDB schema with proper indexes
• Implemented deduplication using upsert logic
• Wrote unit tests for all feed parsers

Feeds Connected:

---

## Feed               | Type              | API Key

Feodo Tracker      | C2 Botnet IPs     | Not Required
Emerging Threats   | Compromised IPs   | Not Required
AlienVault OTX     | Community Pulses  | Required
VirusTotal         | AV Detections     | Required
AbuseIPDB          | Reported IPs      | Required
-------------------------------------------------

Risk Scoring System:

---

## Factor                    | Points

Base score                | 50
High risk category        | +25
Trusted feed              | +15
VirusTotal detections     | +30 max
Maximum possible          | 100
-------------------------------

Result: 2088 real threat indicators collected

========================================
WEEK 2 — NORMALIZATION & SIEM INTEGRATION
=========================================

Objective: Visualize threats in real-time dashboard

What we did:

• Set up ELK Stack using Docker
• Built Python SIEM exporter (MongoDB → Elasticsearch)
• Created Kibana index patterns and dashboards
• Built IP enrichment module with geo data
• Developed cross-feed deduplication report
• Implemented schema validator for data quality
• Wrote unit tests for all modules

ELK Stack Components:

---

## Component         | Purpose              | Port

Elasticsearch     | Search & analytics   | 9200
Kibana            | Visual dashboards    | 5601
Logstash          | Data pipeline        | Internal
---------------------------------------------------

Kibana Dashboards Created:

• Threat Overview — total counts and risk levels
• High Risk Feed — indicators above score 70
• Timeline — threats over time by feed

Result: 2088 indicators visible in Kibana dashboard

========================================
WEEK 3 — DYNAMIC POLICY ENFORCER
================================

Objective: Automatically block malicious IPs

What we did:

• Built iptables wrapper in Python
• Developed continuous enforcement daemon
• Implemented rollback mechanism for false positives
• Built MongoDB client for reading indicators
• Added full audit logging for every action
• Wrote unit tests for enforcer and rollback

How it works (every 2 minutes automatically):

1. Read high-risk IPs from MongoDB (score ≥ 70)
2. Add iptables DROP rule for each IP
3. Record rule in rollback.json
4. Update MongoDB blocked = True
5. Write audit log entry

iptables Chain Example:

Chain TIP_BLOCKLIST
1  DROP  100.19.147.208   TIP-5f9ae9e3
2  DROP  101.47.13.68     TIP-9faa4126
3  DROP  102.208.186.12   TIP-e1e251ab
4  DROP  103.121.91.144   TIP-e7be309c
... 500+ rules

Result: 500+ malicious IPs blocked automatically

========================================
WEEK 4 — SOC DASHBOARD & ALERTING
=================================

Objective: Build SOC interface for security analysts

What we did:

• Built FastAPI REST backend with 7 endpoints
• Designed dark-themed SOC dashboard UI
• Implemented email alerting system for critical threats
• Added rollback button for SOC analysts
• Wrote complete test suite using pytest
• Created startup script for easy deployment

API Endpoints:

---

## Method | Endpoint               | Description

GET    | /api/stats             | Dashboard statistics
GET    | /api/indicators        | List all indicators
GET    | /api/top-threats       | Top 10 threats
GET    | /api/audit             | Audit log
GET    | /api/blocked           | Blocked IPs
POST   | /api/rollback/{ip}     | Rollback a block
GET    | /api/health            | System health
-----------------------------------------------

Result: Live SOC dashboard at http://localhost:8000

---

## PROJECT STRUCTURE

project1/
  |
  |-- week1/                    # OSINT Ingestion
  |   |-- ingest.py             # Main ingestion script
  |   |-- normalizer.py         # Risk scoring
  |   |-- setup_env.sh          # Environment setup
  |   |-- feeds/
  |   |   |-- feodo.py
  |   |   |-- emergingthreats.py
  |   |   |-- otx.py
  |   |   |-- virustotal.py
  |   |   `-- abuseipdb.py
  |   |-- db/
  |   |   `-- mongo.py
  |   `-- tests/
  |       `-- test_feeds.py
  |
  |-- week2/                    # SIEM Integration
  |   |-- siem_exporter.py      # MongoDB to ES
  |   |-- enrichment.py         # IP geo data
  |   |-- normalization/
  |   |   |-- deduplicator.py
  |   |   `-- schema_validator.py
  |   |-- elk_configs/
  |   |   |-- docker-compose-elk.yml
  |   |   |-- logstash.conf
  |   |   `-- logstash.yml
  |   `-- tests/
  |       `-- test_week2.py
  |
  |-- week3/                    # Policy Enforcer
  |   |-- main.py               # Main daemon
  |   |-- enforcer.py           # iptables wrapper
  |   |-- rollback.py           # Rollback manager
  |   |-- db.py                 # MongoDB client
  |   `-- tests/
  |       `-- test_week3.py
  |
  |-- week4/                    # SOC Dashboard
  |   |-- api.py                # FastAPI backend
  |   |-- alerting.py           # Email alerts
  |   |-- static/
  |   |   `-- index.html        # Dashboard UI
  |   `-- tests/
  |       `-- test_week4.py
  |
  `-- start.sh                  # One command startup

---

## TECHNOLOGY STACK

---

## Category        | Technology      | Purpose

Language        | Python 3.12     | All scripts
Database        | MongoDB         | Threat storage
Search          | Elasticsearch   | Fast queries
SIEM            | Kibana          | Visualization
Pipeline        | Logstash        | Data flow
Firewall        | Linux iptables  | IP blocking
API             | FastAPI         | REST backend
Container       | Docker          | ELK deployment
Testing         | Pytest          | Unit tests
Version Control | Git + GitHub    | Code management
---------------------------------------------------

---

## HOW TO RUN

Prerequisites:

• Linux Ubuntu 24.04
• Python 3.12+
• MongoDB
• Docker
• Git

Quick Start:

Step 1 — Start everything
cd /home/astha/project1
bash start.sh

Step 2 — Run ingestion
cd week1
source venv/bin/activate
python ingest.py

Step 3 — Run enforcer
cd ../week3
sudo /home/astha/project1/week1/venv/bin/python main.py --live

Open in Browser:

SOC Dashboard  : http://localhost:8000
Kibana SIEM    : http://localhost:5601
API Docs       : http://localhost:8000/docs

---

## RESULTS

---

## Metric                              | Value

Total indicators collected          | 2088
High risk indicators (score ≥ 70)   | 577
Malicious IPs blocked               | 500+
OSINT feeds connected               | 5
API endpoints                       | 7
Test coverage                       | 40+ tests
Time to block new threat            | Under 2 minutes
-----------------------------------------------------

---

## SECURITY FEATURES

• Risk scoring system prevents blocking legitimate IPs
• Dry-run mode enables safe testing
• Rollback allows reversal of false positives
• Audit logging ensures PCI-DSS compliance
• Private IP filter protects internal networks
• Deduplication avoids duplicate firewall rules

---

## LICENSE

MIT — Educational Internship Project

=======================================================
END OF README
=============
