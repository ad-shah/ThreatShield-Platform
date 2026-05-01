# Week 3 — Dynamic Policy Enforcer Notes

## What it does
Monitors MongoDB for high risk indicators
and automatically blocks them using iptables.

## How it works
1. Reads high risk IPs from MongoDB (score >= 70)
2. Adds iptables DROP rule for each IP
3. Records rule in rollback.json
4. Updates MongoDB blocked=True
5. Writes audit log entry

## iptables Chain
Name: TIP_BLOCKLIST
Linked to: INPUT chain
Rule format: iptables -A TIP_BLOCKLIST -s <IP> -j DROP

## Risk Threshold
Default: 70
Change with: RISK_THRESHOLD=80 python main.py

## DRY RUN vs LIVE
DRY RUN (default): simulates blocking, no real rules
LIVE: applies real iptables rules (needs sudo)

## Commands

### Run once dry run (safe, default)
python main.py --dry-run

### Run once live (needs sudo)
sudo python main.py --live

### Run continuously
python main.py --loop

### List all blocked rules
python main.py --list

### Rollback specific IP
python main.py --rollback 185.220.101.45

### Show stats
python main.py --stats

## Rollback File
Location: logs/rollback.json
Contains: all applied rules with timestamps

## Audit Log
Location: MongoDB audit_log collection
Contains: all BLOCK and ROLLBACK actions
