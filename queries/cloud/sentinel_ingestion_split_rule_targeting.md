# Sentinel Ingestion Breakdown — CommonSecurityLog & Syslog (Split-Rule Targeting)

**Created:** 2026-07-02  
**Platform:** Both  
**Tables:** CommonSecurityLog, Syslog, Usage  
**Keywords:** ingestion cost, cost optimization, split ingestion, filter transformation, DCR, data collection rule, Auxiliary tier, Data lake tier, tier migration, CEF, firewall logs, DeviceVendor, DeviceProduct, Activity, LogSeverity, syslog facility, ProcessName, noise reduction, _SPLT  
**MITRE:** N/A (cost & ingestion optimization)  
**Domains:** cloud  
**Timeframe:** Last 30 days (configurable)

---

## Overview

This file gives an SOC or platform team a set of **copy-paste KQL queries** that break down ingestion
volume for the two tables that most often dominate Microsoft Sentinel spend — **`CommonSecurityLog`**
(CEF: firewalls, proxies, secure web gateways) and **`Syslog`** (Linux hosts and network appliances).

The goal is to quickly surface **high-volume, low-security-value data** that is a good candidate for a
**filter** or **split** transformation rule, so you can cut Analytics-tier cost without losing detection
coverage.

> **These queries are self-contained** — they run directly in the Defender portal's **Advanced Hunting**
> page or in **Log Analytics / Microsoft Sentinel Logs**. No Copilot, notebooks, or additional tooling
> required. Paste, adjust the `lookback` variable, and read the results.

> 💡 **Using GitHub Copilot with this repo?** The **`sentinel-ingestion-report`** skill automates a much
> deeper version of this analysis (table tiering, analytic-rule cross-reference, rule health, anomaly
> detection, license-benefit modeling) and renders a full report. This query file is the lightweight,
> portable equivalent intended for customers/analysts running an ad-hoc session **without** Copilot.

### Filter vs. Split — pick the right transformation

Microsoft Sentinel supports two native ingestion-time transformations, configured in the Defender
portal (no manual DCR editing required) under **Microsoft Sentinel → Configuration → Tables → select a
table → Filter rule / Split rule**:

| Transformation | What it does | When to use | Where the data goes |
|----------------|--------------|-------------|---------------------|
| **Filter** | KQL condition that evaluates **true = discard**. Dropped data is **not ingested to any tier**. | Truly worthless noise with no hunting/compliance value (e.g., routine "allow" events). | Discarded (gone). |
| **Split** | KQL expression that defines what stays in **Analytics**. Non-matching data is routed to the **Data lake tier** only (cheaper, long retention). Analytics data is also mirrored to the Data lake. | Operational data you still want for hunting/compliance but not at Analytics cost/retention. | Analytics + Data lake (matching) / Data lake only (non-matching). |

**Split output table:** a split rule creates a companion table with a **`_SPLT`** suffix (e.g.,
`CommonSecurityLog_SPLT`) for the Data-lake-only data, so you can set retention/access independently.

> ⚠️ **Key operational notes** (from Microsoft Learn):
> - **Propagation delay:** transformations can take **up to one hour** to take effect.
> - **XDR table visibility:** split/filter on XDR tables don't appear in Advanced Hunting for the first
>   30 days of data (Log Analytics / Sentinel Logs reflect the savings immediately). `CommonSecurityLog`
>   and `Syslog` are Sentinel tables, so this caveat mainly matters for Defender XDR-native tables.
> - **DCR conflicts:** a Sentinel transformation can conflict with an existing Azure Monitor DCR
>   transformation on the same table — check the combined effect before saving.
> - **Permissions:** requires **Log Analytics Contributor** on the workspace plus **Data (manage)** in
>   unified RBAC.
> - **Verify after applying:** re-run the relevant breakdown query below and confirm the noisy dimension
>   dropped out of Analytics (and, for a split, appears in the `_SPLT` table).

**Reference documentation:**
- [Transform data using filter and split in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/transformation-filter-split)
- [Custom data ingestion and transformation in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/data-transformation)
- [Reduce costs for Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/billing-reduce-costs)

### ⚠️ Reading the numbers

| Note | Detail |
|------|--------|
| `estimate_data_size()` is **approximate** | Good for **relative** comparison within a table. For authoritative **billed** volume, use the `Usage` table (Query 1). |
| `LogSeverity` is a **string** | Vendors send either numerics (`"0"`–`"10"`) or text (`"Low"`/`"Medium"`/`"High"`). `toint()` may return blank — fall back to grouping on the raw string. |
| `CommunicationDirection` is often **empty** | Many CEF sources don't populate it. Keep it in the grouping only if your data uses it. |
| Retention window | Queries default to **30 days**. Advanced Hunting / Logs cover ≤30d for free; for a 90-day view run the same KQL in **Microsoft Sentinel Logs / Data lake**. |

### ✅ Before you split or filter anything — check detections

A dimension being high-volume does **not** make it safe to remove. **Cross-check every candidate**
(`Activity`, `Facility`, `ProcessName`, `LogSeverity`, `DeviceVendor`) against your **analytic rules**
and **custom detections** first:

- If a rule filters on it → **keep it in Analytics**, or use **split** (retains it in the Data lake) — never **filter** (discards it).
- Prefer **split over filter** as the default low-risk move: it preserves the data for hunting/compliance at a fraction of the cost.

---

## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [Billed Volume Anchor — Table vs Workspace](#query-1-billed-volume-anchor--table-vs-workspace) | Dashboard | `Usage` |
| 2 | [CommonSecurityLog Volume by Vendor & Product](#query-2-commonsecuritylog-volume-by-vendor--product) | Dashboard | `CommonSecurityLog` |
| 3 | [CommonSecurityLog Volume by Vendor, Activity & Direction](#query-3-commonsecuritylog-volume-by-vendor-activity--direction) | Dashboard | `CommonSecurityLog` |
| 4 | [CommonSecurityLog Volume by Log Severity](#query-4-commonsecuritylog-volume-by-log-severity) | Dashboard | `CommonSecurityLog` |
| 5 | [CommonSecurityLog Volume by Device Event Class (Signature)](#query-5-commonsecuritylog-volume-by-device-event-class-signature) | Dashboard | `CommonSecurityLog` |
| 6 | [CommonSecurityLog Split-Candidate Summary](#query-6-commonsecuritylog-split-candidate-summary) | Dashboard | `CommonSecurityLog` |
| 7 | [Syslog Volume by Facility & Severity](#query-7-syslog-volume-by-facility--severity) | Dashboard | `Syslog` |
| 8 | [Syslog Volume by Process & Facility](#query-8-syslog-volume-by-process--facility) | Dashboard | `Syslog` |
| 9 | [Syslog Volume by Source Host](#query-9-syslog-volume-by-source-host) | Dashboard | `Syslog` |
| 10 | [Syslog Split-Candidate Summary](#query-10-syslog-split-candidate-summary) | Dashboard | `Syslog` |


## Part A — CommonSecurityLog (CEF: firewalls / proxies / gateways)

### Query 1: Billed Volume Anchor — Table vs Workspace

**Purpose:** Establish the authoritative (billed) volume of each table and its share of the workspace, so you confirm CommonSecurityLog / Syslog really are the top spenders before drilling in.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Cost/ingestion aggregation over the Usage metering table — not a detection. Not suitable for custom detection."
-->

```kql
Usage
| where TimeGenerated > ago(30d)
| where IsBillable == true
| summarize BilledGB = round(sum(Quantity) / 1024.0, 2) by DataType
| extend PctOfWorkspace = round(100.0 * BilledGB / toscalar(
    Usage | where TimeGenerated > ago(30d) | where IsBillable == true | summarize sum(Quantity) / 1024.0), 1)
| order by BilledGB desc
```

### Query 2: CommonSecurityLog Volume by Vendor & Product

**Purpose:** Identify which appliance/product dominates CEF volume — the first axis for scoping a transformation rule.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Volume aggregation for cost analysis — not a detection. Not suitable for custom detection."
-->

```kql
let lookback = 30d;
let _total = toscalar(CommonSecurityLog | where TimeGenerated > ago(lookback) | summarize sum(estimate_data_size(*)) / 1024.0 / 1024.0 / 1024.0);
CommonSecurityLog
| where TimeGenerated > ago(lookback)
| summarize EventCount = count(), EstimatedGB = round(sum(estimate_data_size(*)) / 1024.0 / 1024.0 / 1024.0, 3) by DeviceVendor, DeviceProduct
| extend PctOfTable = round(100.0 * EstimatedGB / _total, 1)
| order by EstimatedGB desc
```

### Query 3: CommonSecurityLog Volume by Vendor, Activity & Direction

**Purpose:** The core split dimension. High-volume operational `Activity` values (e.g. *Firewall session allowed*, *Web access logged*, *TRAFFIC*) are prime split/filter candidates, while threat/deny events stay in Analytics.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Volume aggregation for cost analysis — not a detection. Not suitable for custom detection."
-->

```kql
let lookback = 30d;
let _total = toscalar(CommonSecurityLog | where TimeGenerated > ago(lookback) | summarize sum(estimate_data_size(*)) / 1024.0 / 1024.0 / 1024.0);
CommonSecurityLog
| where TimeGenerated > ago(lookback)
| summarize EventCount = count(), EstimatedGB = round(sum(estimate_data_size(*)) / 1024.0 / 1024.0 / 1024.0, 3)
    by DeviceVendor, DeviceProduct, Activity, CommunicationDirection
| extend PctOfTable = round(100.0 * EstimatedGB / _total, 1)
| order by EstimatedGB desc
| take 40
```

### Query 4: CommonSecurityLog Volume by Log Severity

**Purpose:** Find the low-severity, high-volume band. Routing low severity to the Data lake (split) or discarding it (filter) is a common, high-impact optimization.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Volume aggregation for cost analysis — not a detection. Not suitable for custom detection."
-->

```kql
let lookback = 30d;
CommonSecurityLog
| where TimeGenerated > ago(lookback)
| extend SevNum = toint(LogSeverity)   // LogSeverity is a STRING; may be "0"-"10" or text like "Low"/"High"
| summarize EventCount = count(), EstimatedGB = round(sum(estimate_data_size(*)) / 1024.0 / 1024.0 / 1024.0, 3)
    by LogSeverity, SevNum, DeviceVendor
| order by EstimatedGB desc
```

### Query 5: CommonSecurityLog Volume by Device Event Class (Signature)

**Purpose:** Drill to the single noisiest event signature within a vendor — useful when one `DeviceEventClassID` drives most of an appliance's volume.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Volume aggregation for cost analysis — not a detection. Not suitable for custom detection."
-->

```kql
let lookback = 30d;
CommonSecurityLog
| where TimeGenerated > ago(lookback)
| summarize EventCount = count(), EstimatedGB = round(sum(estimate_data_size(*)) / 1024.0 / 1024.0 / 1024.0, 3)
    by DeviceVendor, DeviceEventClassID, Activity
| order by EstimatedGB desc
| take 30
```

### Query 6: CommonSecurityLog Split-Candidate Summary

**Purpose:** Auto-classify each Vendor × Activity combination into a keep/split hint so candidates jump out. Treat the hint as a starting point — always validate against detections.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Heuristic keyword classification over volume aggregation for cost triage — not a detection. Not suitable for custom detection."
-->

```kql
let lookback = 30d;
let _total = toscalar(CommonSecurityLog | where TimeGenerated > ago(lookback) | summarize sum(estimate_data_size(*)) / 1024.0 / 1024.0 / 1024.0);
CommonSecurityLog
| where TimeGenerated > ago(lookback)
| summarize EventCount = count(), EstimatedGB = round(sum(estimate_data_size(*)) / 1024.0 / 1024.0 / 1024.0, 3)
    by DeviceVendor, Activity
| extend PctOfTable = round(100.0 * EstimatedGB / _total, 1)
| extend SplitHint = case(
    Activity has_any ("allow", "permit", "traffic", "web access", "session established", "logged", "dns"), "Candidate -> Data lake (operational)",
    Activity has_any ("threat", "malware", "ioc", "intrusion", "deny", "denied", "block", "attack", "exploit"), "Keep -> Analytics (security)",
    "Review")
| order by EstimatedGB desc
```

---

## Part B — Syslog (Linux hosts / network appliances)

### Query 7: Syslog Volume by Facility & Severity

**Purpose:** Facility × severity maps directly to DCR facility/level selectors and to split-rule conditions. Find the noisy operational facilities and low-severity bands.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Volume aggregation for cost analysis — not a detection. Not suitable for custom detection."
-->

```kql
let lookback = 30d;
let _total = toscalar(Syslog | where TimeGenerated > ago(lookback) | summarize sum(estimate_data_size(*)) / 1024.0 / 1024.0 / 1024.0);
Syslog
| where TimeGenerated > ago(lookback)
| summarize EventCount = count(), EstimatedGB = round(sum(estimate_data_size(*)) / 1024.0 / 1024.0 / 1024.0, 3), Hosts = dcount(Computer)
    by Facility, SeverityLevel
| extend PctOfTable = round(100.0 * EstimatedGB / _total, 1)
| order by EstimatedGB desc
```

### Query 8: Syslog Volume by Process & Facility

**Purpose:** Surface filterable process-level noise (e.g. agent daemons, desktop-session processes, `systemd`) that can be excluded from Analytics with a process-scoped split condition.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Volume aggregation for cost analysis — not a detection. Not suitable for custom detection."
-->

```kql
let lookback = 30d;
let _total = toscalar(Syslog | where TimeGenerated > ago(lookback) | summarize sum(estimate_data_size(*)) / 1024.0 / 1024.0 / 1024.0);
Syslog
| where TimeGenerated > ago(lookback)
| summarize EventCount = count(), EstimatedGB = round(sum(estimate_data_size(*)) / 1024.0 / 1024.0 / 1024.0, 3), Hosts = dcount(Computer)
    by Facility, ProcessName
| extend PctOfTable = round(100.0 * EstimatedGB / _total, 1)
| order by EstimatedGB desc
| take 40
```

### Query 9: Syslog Volume by Source Host

**Purpose:** Spot a single chatty host driving disproportionate volume — a candidate for host-scoped filtering or source-side log tuning.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Volume aggregation for cost analysis — not a detection. Not suitable for custom detection."
-->

```kql
let lookback = 30d;
Syslog
| where TimeGenerated > ago(lookback)
| extend SourceHost = iff(isnotempty(HostName) and HostName != Computer, HostName, Computer)
| summarize EventCount = count(), EstimatedGB = round(sum(estimate_data_size(*)) / 1024.0 / 1024.0 / 1024.0, 3),
    Facilities = make_set(Facility, 10) by SourceHost
| order by EstimatedGB desc
| take 25
```

### Query 10: Syslog Split-Candidate Summary

**Purpose:** Auto-classify each facility into a keep/split hint. Auth facilities stay in Analytics; operational facilities are split/filter candidates. Validate against detections before acting.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Heuristic keyword classification over volume aggregation for cost triage — not a detection. Not suitable for custom detection."
-->

```kql
let lookback = 30d;
let _total = toscalar(Syslog | where TimeGenerated > ago(lookback) | summarize sum(estimate_data_size(*)) / 1024.0 / 1024.0 / 1024.0);
Syslog
| where TimeGenerated > ago(lookback)
| summarize EventCount = count(), EstimatedGB = round(sum(estimate_data_size(*)) / 1024.0 / 1024.0 / 1024.0, 3)
    by Facility
| extend PctOfTable = round(100.0 * EstimatedGB / _total, 1)
| extend SplitHint = case(
    Facility in ("authpriv", "auth"), "Keep -> Analytics (auth / sshd / sudo)",
    Facility in ("cron", "daemon", "user", "mail", "lpr", "news", "uucp"), "Candidate -> Data lake (operational)",
    Facility == "kern", "Keep notice+ / split low-severity",
    "Review")
| order by EstimatedGB desc
```

---

## How to read this for split/filter rules

| Signal in the output | Suggested action |
|----------------------|------------------|
| One `Activity` / `Facility` is a large % of the table | Prime candidate to route to the Data lake tier (split) |
| Low `LogSeverity` / low `SeverityLevel` + high volume | Split low severity to Data lake; keep high severity in Analytics |
| Operational events (allow / traffic / web / cron / user) | Split to Data lake (retain cheaply) or filter (discard if no value) |
| Security events (threat / deny / malware / authpriv) | Keep in Analytics |
| A single chatty host or process | Host/process-scoped condition in the split/filter rule (or tune at the source) |

### Recommended workflow

1. **Anchor** — Query 1 confirms the top-spending tables and their billed GB.
2. **Break down** — Queries 2–5 (CEF) and 7–9 (Syslog) show where the volume concentrates.
3. **Shortlist** — Queries 6 and 10 give a first-pass keep/split classification.
4. **Validate against detections** — for each candidate value, confirm no analytic rule or custom detection depends on it. If one does, prefer **split** (keeps it in the Data lake) over **filter** (discards it).
5. **Apply** — create the rule in **Microsoft Sentinel → Configuration → Tables → Split rule / Filter rule**.
6. **Verify** — after up to ~1 hour of propagation, re-run the relevant breakdown query and confirm the noisy dimension dropped from Analytics (and appears in the `_SPLT` table for a split).

> **Next step beyond these queries:** the analytic-rule and custom-detection cross-reference in step 4 is
> the critical safety check. Review each rule's KQL for references to the candidate table/value before
> removing it from the Analytics tier.
