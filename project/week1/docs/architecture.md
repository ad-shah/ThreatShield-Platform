# Week 1 — Architecture Notes

## Data Flow
Internet (OSINT Feeds)
|
| HTTP GET requests
v
Feed Connectors
feeds/feodo.py, feeds/otx.py, etc.
|
| normalize_indicator()
v
normalizer.py
Validates, cleans, scores
|
| store.upsert_indicators()
v
MongoDB
threat_intel.indicators collection

## Key Design Decisions

### 1. Upsert instead of Insert
Same indicator from same feed = update existing record.
New indicator = insert fresh record.
Automatic deduplication.

### 2. Normalize before storing
Raw feed data varies across feeds.
We normalize BEFORE storing so database
always has clean consistent documents.

### 3. Compound unique index
(indicator, source) pair is unique.
Same IP from Feodo AND AbuseIPDB = 2 documents.
Tracks which feeds reported what.

## Risk Score Breakdown

| Factor                        | Points   |
|-------------------------------|----------|
| Baseline                      | 50       |
| High risk category            | +25      |
| Trusted feed (Feodo/ET)       | +15      |
| VT detection ratio            | +30 max  |
| Feed provided score           | Replaces |
| Maximum                       | 100      |

## Indicator Types

| Type   | Example              |
|--------|----------------------|
| ip     | 185.220.101.45       |
| domain | evil.botnet.ru       |
| url    | http://evil.com/pay  |
| hash   | d41d8cd98f00b204...  |
