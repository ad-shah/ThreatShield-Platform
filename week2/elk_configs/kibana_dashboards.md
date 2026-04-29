# Kibana Dashboard Setup Guide

## Step 1 — Open Kibana
http://localhost:5601

## Step 2 — Create Index Pattern
1. Go to Menu -> Stack Management -> Index Patterns
2. Click Create index pattern
3. Pattern: threat-indicators-*
4. Time field: @timestamp
5. Click Save

## Step 3 — Dashboard 1: Threat Overview
Create -> Dashboard -> Create new dashboard

Panel 1: Total Count
- Add panel -> Metric -> Count
- Title: Total Indicators

Panel 2: Risk Level Pie Chart
- Add panel -> Pie
- Buckets -> Split slices -> Terms -> risk_level.keyword
- Title: Indicators by Risk Level

Panel 3: Feed Source Bar Chart
- Add panel -> Vertical bar
- X-axis -> Terms -> feed_source.keyword
- Title: Indicators per Feed

Panel 4: Type Donut Chart
- Add panel -> Pie
- Buckets -> Terms -> indicator_type.keyword
- Title: Indicator Type Distribution

## Step 4 — Dashboard 2: High Risk Feed
Create -> Dashboard -> Create new dashboard
Add filter: risk_score >= 70

Panel: High Risk Data Table
- Add panel -> Data table
- Buckets -> Terms -> indicator.keyword
- Title: Top High Risk Indicators

Panel: Risk Score Histogram
- Add panel -> Histogram
- X-axis -> risk_score -> interval 10
- Title: Risk Score Distribution

## Step 5 — Dashboard 3: Timeline
Create -> Dashboard -> Create new dashboard

Panel: Indicators Over Time
- Add panel -> Line chart
- X-axis -> Date histogram -> @timestamp
- Split series -> Terms -> feed_source.keyword
- Title: New Indicators by Feed

## Useful KQL Queries
# Find C2 indicators
categories: "c2"

# High risk IPs
indicator_type: "ip" AND risk_score >= 70

# Critical from Feodo
feed_source: "feodo" AND risk_level: "CRITICAL"

# All blocked
is_blocked: true
