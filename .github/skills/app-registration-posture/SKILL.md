---
name: app-registration-posture
description: 'Use this skill when asked to audit, assess, or report on app registration and service principal security posture in Entra ID. Triggers on keywords like "app registration posture", "app registration abuse", "service principal permissions", "dangerous app permissions", "app ownership", "app credential abuse", "SPN lateral movement", "app consent grant", "overprivileged apps", "cross-tenant SPN", "app registration kill chain", "app persistence", "credential add chain", "app registration security", "Graph API permissions audit", or when investigating app registration ownership, credential rotation patterns, permission escalation chains, cross-tenant service principal access, or compromised user to app abuse paths. This skill combines Graph API posture inventory (current-state dangerous permission grants, app ownership, credential hygiene) with KQL chain detection queries (AuditLogs, AADServicePrincipalSignInLogs, AADUserRiskEvents, MicrosoftGraphActivityLogs) to produce a comprehensive app registration security posture assessment covering permission concentration, owner risk, credential hygiene, cross-tenant exposure, and active abuse signal detection. App Permission Risk Score with 5 dimensions. Supports inline chat and markdown file output.'
---

# App Registration Security Posture — Instructions

## Purpose

This skill audits the **security posture of Entra ID App Registrations and Service Principals** across your organization, combining **Graph API current-state inventory** with **KQL attack chain detection** to create a comprehensive assessment.

App Registrations are a growing persistence and lateral movement vector. Attackers who compromise a user with app ownership can add credentials (secrets/certificates), disconnect from the user session, and authenticate as the service principal — inheriting all the app's permissions. This is the exact pattern documented in the [Guardz research](https://guardz.com/blog/abusing-entra-id-app-registrations-for-long-term-persistence/) and used in the [SolarWinds/Solorigate attack](https://www.microsoft.com/en-us/security/blog/2020/12/28/using-microsoft-365-defender-to-coordinate-protection-against-solorigate/).

**What this skill covers:**

| Domain | Key Questions Answered | Data Source |
|--------|----------------------|-------------|
| 🔐 **Permission Inventory** | Which apps have dangerous Graph API permissions? How concentrated are critical permissions? | Graph API |
| 👤 **Owner Risk** | Which app owners are non-admin users (phishing targets)? Are owners currently risky? Ownerless apps? | Graph API + Q1 |
| 🔑 **Credential Hygiene** | Stale secrets, multi-credential apps, long-lived credentials, cert+secret anomalies | Graph API |
| 🌐 **Cross-Tenant Exposure** | Foreign SPNs authenticating into your tenant with dangerous permissions | Q4 |
| ⚡ **Active Abuse Chains** | Risky user → app ops, credential add → SPN activation, ownership → credential chains, Graph API lateral movement, permission escalation, multi-app ownership spread, App Governance & OAuth incident cross-reference | Q1–Q8 |

**How this differs from existing capabilities:**

| Existing Resource | Coverage | Gap This Skill Fills |
|-------------------|----------|----------------------|
| `app_credential_management.md` | Individual credential/ownership/consent events | No cross-table chain correlation |
| `service_principal_scope_drift.md` | SPN behavioral baseline drift | No link to preceding compromise signals |
| App Governance (Microsoft) | Anomalous app behavior, overprivileged apps | No correlation with user risk signals or multi-step chains |
| **This skill** | **Graph API posture + KQL chain detection** | **End-to-end: current state → historical abuse → risk scoring** |

**Data sources:**

| Source | Type | What It Provides |
|--------|------|-----------------|
| `AuditLogs` (ApplicationManagement) | KQL | Credential adds, ownership changes, consent grants, permission assignments |
| `AADServicePrincipalSignInLogs` | KQL | SPN authentication patterns, cross-tenant sign-ins, credential types |
| `AADUserRiskEvents` | KQL | Identity Protection risk detections for app owners |
| `MicrosoftGraphActivityLogs` | KQL | Graph API calls by SPNs post-credential-add |
| `AlertInfo` + `AlertEvidence` | KQL | App Governance alerts, OAuth incidents, Attack Disruption events (Q8) |
| Graph API (`/servicePrincipals`, `/applications`) | REST | Current-state permission grants, app ownership, credential inventory |

**References:**
- [Guardz: Abusing Entra ID App Registrations for Long-Term Persistence](https://guardz.com/blog/abusing-entra-id-app-registrations-for-long-term-persistence/)
- [Microsoft: Solorigate Coordinated Defense](https://www.microsoft.com/en-us/security/blog/2020/12/28/using-microsoft-365-defender-to-coordinate-protection-against-solorigate/)
- [Microsoft: App Governance in Defender for Cloud Apps](https://learn.microsoft.com/en-us/defender-cloud-apps/app-governance-manage-app-governance)
- [MITRE ATT&CK T1098.001 — Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001/)
- [MITRE ATT&CK T1550.001 — Application Access Token](https://attack.mitre.org/techniques/T1550/001/)
- [Microsoft: Verify First-Party Apps in Sign-In Reports](https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/governance/verify-first-party-apps-sign-in)

### 🔴 URL Registry — Canonical Links for Report Generation

**MANDATORY:** When generating reports, copy URLs **verbatim** from this registry. NEVER construct, guess, or paraphrase a URL. If a URL is not in this registry, omit the hyperlink entirely and use plain text.

| Label | Canonical URL |
|-------|---------------|
| `BLOG_GUARDZ` | `https://guardz.com/blog/abusing-entra-id-app-registrations-for-long-term-persistence/` |
| `BLOG_SOLORIGATE` | `https://www.microsoft.com/en-us/security/blog/2020/12/28/using-microsoft-365-defender-to-coordinate-protection-against-solorigate/` |
| `DOCS_APP_GOVERNANCE` | `https://learn.microsoft.com/en-us/defender-cloud-apps/app-governance-manage-app-governance` |
| `DOCS_GRAPH_PERMS` | `https://learn.microsoft.com/en-us/graph/permissions-reference` |
| `DOCS_FIRST_PARTY_APPS` | `https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/governance/verify-first-party-apps-sign-in` |
| `MITRE_T1098_001` | `https://attack.mitre.org/techniques/T1098/001/` |
| `MITRE_T1550_001` | `https://attack.mitre.org/techniques/T1550/001/` |

---

## Threat Landscape: Why App Registration Posture Matters

The attack pattern is well-documented and increasingly exploited:

```
User compromised → discovers app ownership → adds credential (secret/cert) →
disconnects from user session → authenticates AS the app (SPN) →
uses app permissions for lateral movement / data exfiltration / privilege escalation
```

**Why app registrations are attractive to attackers:**

| Factor | Risk |
|--------|------|
| **Persistence beyond user compromise** | Revoking the user's password doesn't revoke the app credential — the SPN continues to operate |
| **Non-admin users as owners** | Standard users can own apps with `Application.ReadWrite.All` — if phished, the attacker inherits those permissions |
| **Permissions outlive their creators** | App permissions persist even after the admin who granted them leaves the org |
| **Cross-tenant trust** | Multi-tenant apps create implicit trust relationships that survive account remediation |
| **Low visibility** | SPN sign-ins are in a separate log table (`AADServicePrincipalSignInLogs`) that many SOCs don't monitor |

**MITRE ATT&CK Mapping:**

| Technique | ID | Kill Chain Stage | Detection Query |
|-----------|----|-----------------|-----------------|
| Additional Cloud Credentials | T1098.001 | Persistence | Q2, Q3 |
| Additional Cloud Roles | T1098.003 | Privilege Escalation | Q6 |
| Cloud Accounts | T1078.004 | Initial Access / Persistence | Q1 |
| Application Access Token | T1550.001 | Lateral Movement | Q2, Q5 |
| SAML/OAuth Tokens | T1606.002 | Credential Access | Q4 |
| Impersonation | T1656 | Defense Evasion | Q4 |

> **Q8 note:** Q8 (App Governance & OAuth Incident Cross-Reference) is a detection validation query, not a technique-specific detector. It cross-references existing Defender detections spanning multiple techniques above against Phase 1 findings.

---

## 📑 TABLE OF CONTENTS

1. **[Critical Workflow Rules](#-critical-workflow-rules---read-first-)** — Mandatory rules
2. **[Schema Pitfalls](#schema-pitfalls)** — AuditLogs and Graph API pitfalls
3. **[Dangerous Permissions Reference](#dangerous-permissions-reference)** — Application-level Graph API grants
4. **[App Permission Risk Score Formula](#app-permission-risk-score-formula)** — Composite risk scoring
5. **[Execution Workflow](#execution-workflow)** — Phase-by-phase plan
6. **[Phase 1: Graph API Posture Inventory](#phase-1-graph-api-posture-inventory)** — Steps P1–P7
7. **[Phase 2: KQL Chain Detection Queries](#phase-2-kql-chain-detection-queries)** — Queries Q1–Q8
8. **[Output Modes](#output-modes)** — Inline vs Markdown report
9. **[Inline Report Template](#inline-report-template)** — Chat-rendered format
10. **[Markdown File Report Template](#markdown-file-report-template)** — Disk-saved format
11. **[Known Pitfalls](#known-pitfalls)** — Schema quirks and edge cases
12. **[Quality Checklist](#quality-checklist)** — Pre-delivery validation
13. **[SVG Dashboard Generation](#svg-dashboard-generation)** — Visual dashboard from report

---

## ⚠️ CRITICAL WORKFLOW RULES - READ FIRST ⚠️

1. **Dual data source skill:** This skill uses BOTH **Graph API** (via Graph MCP) for current-state posture AND **KQL** (via `RunAdvancedHuntingQuery`) for historical chain detection. Both phases are required for a complete assessment.

2. **Graph API before KQL:** Run Phase 1 (Graph API posture) first — it identifies the dangerous apps. Phase 2 (KQL chains) then checks whether those apps show historical abuse signals.

3. **Use `RunAdvancedHuntingQuery` for all KQL queries.** All tables used (AuditLogs, AADServicePrincipalSignInLogs, AADUserRiskEvents, MicrosoftGraphActivityLogs, AlertInfo, AlertEvidence) are available in Advanced Hunting. AH is free for Analytics-tier tables. Data Lake fallback only if AH fails or lookback > 30 days (note: AlertInfo/AlertEvidence are AH-only).

4. **ASK the user for output format** before generating the report:
   - **Inline chat summary** (quick review in chat)
   - **Markdown file report** (detailed, archived to `reports/app-registration-posture/`)
   - **Both** (markdown + inline summary)

5. **⛔ MANDATORY: Evidence-based analysis only** — Report ONLY what query results show. Use the explicit absence pattern (`✅ No [finding] detected`) when queries return 0 results. Never guess or assume.

6. **AuditLogs dynamic fields require special handling** — Always extract with `tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName)`. See [Schema Pitfalls](#schema-pitfalls).

7. **Graph API: query from the permission side, not the app side** — Don't enumerate all app registrations (could be 1000+). Query `appRoleAssignedTo` on the Microsoft Graph service principal to get all dangerous grants in ~3 API calls. See [Phase 1 Scaling Strategy](#phase-1-graph-api-posture-inventory).

8. **Run KQL queries in parallel batches** where possible — Q1–Q8 are all independent and can run in parallel.

9. **Time tracking** — Report elapsed time after each phase completion.

### ⛔ PROHIBITED ACTIONS

| Action | Status |
|--------|--------|
| Enumerating all app registrations individually via Graph API | ❌ **PROHIBITED** — use appRoleAssignedTo approach |
| Querying `requiredResourceAccess` for granted permissions | ❌ **PROHIBITED** — shows requested, not granted perms |
| Querying ServicePrincipal for ownership (`/servicePrincipals/{id}?$expand=owners`) | ❌ **PROHIBITED** — ownership is on Application object |
| Joining AuditLog operations on `TargetResources[0].id` across operation types | ❌ **PROHIBITED** — AppId ≠ SPNId for same app |
| Reporting 0 KQL results without sanity-checking the query logic | ❌ **PROHIBITED** |
| Fabricating URLs not in the URL Registry | ❌ **PROHIBITED** |

---

## Schema Pitfalls

**Read these before modifying any query in this skill.**

| Pitfall | Details | Workaround |
|---------|---------|------------|
| **Application ObjectId ≠ ServicePrincipal ObjectId** | The same app has different GUIDs in `TargetResources[0].id` depending on operation type. Credential operations → Application ObjectId; permission/consent operations → ServicePrincipal ObjectId | Join on `displayName` or `Actor` when correlating across operation types (see Q6) |
| **Ownership target name in modifiedProperties** | For "Add owner to application", `TargetResources[0]` is the new owner (User type). The app name is in `TargetResources[0].modifiedProperties[1].newValue` (field `Application.DisplayName`) | Extract with `tostring(parse_json(tostring(ModProps[1].newValue)))` |
| **OperationName trailing spaces** | Credential operations have trailing spaces: `"Update application – Certificates and secrets management "` | Preserve trailing spaces in filters or use `has` instead of `==` |
| **`InitiatedBy` is dynamic** | Always extract with `tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName)` | Never use dot-notation directly |
| **Consent targets structure** | "Consent to application": `Target[0]` = the app receiving consent. "Add delegated permission grant": `Target[0]` = the resource API (e.g., Microsoft Graph), `Target[1]` = the app | Check OperationName before assuming Target[0] is the app |
| **Cross-tenant SPNs have no local app object** | `GET /v1.0/applications?$filter=displayName eq 'X'` returns empty for SPNs owned by foreign tenants | Identify via `AADServicePrincipalSignInLogs` where `AppOwnerTenantId != AADTenantId` (Q4). These can only be managed by the owning tenant |
| **SP owners ≠ Application owners** | `/servicePrincipals/{id}?$expand=owners` often returns empty even when the Application has owners | Always query the **Application** object for ownership |
| **`requiredResourceAccess` ≠ granted permissions** | The Application object's `requiredResourceAccess` shows what the app **requests**, not what's been **granted** | Use `appRoleAssignedTo` for granted permissions — this is the authoritative source |
| **Red team apps may have owners stripped** | Attack simulation tools often remove ownership post-creation | Fall back to AuditLogs `"Add application"` operation to find the original creator |

---

## Dangerous Permissions Reference

**Application-level Graph API grants that this skill flags:**

| Permission | Risk | Attack Use |
|------------|------|------------|
| `Application.ReadWrite.All` | 🔴 Critical | Create/modify any app registration — further persistence |
| `AppRoleAssignment.ReadWrite.All` | 🔴 Critical | Grant itself or any app **any permission** — golden ticket |
| `RoleManagement.ReadWrite.Directory` | 🔴 Critical | Assign any directory role to any principal |
| `Directory.ReadWrite.All` | 🔴 Critical | Read/write all directory objects |
| `Policy.ReadWrite.ConditionalAccess` | 🔴 Critical | Disable CA policies — defense evasion |
| `Mail.ReadWrite` | 🟠 High | Read any user's mailbox — data exfiltration |
| `Mail.Send` | 🟠 High | Send email as any user — phishing, BEC |
| `Mail.Read` | 🟠 High | Read any user's mail — reconnaissance |
| `MailboxSettings.ReadWrite` | 🟠 High | Create forwarding rules — silent exfiltration |
| `User.ReadWrite.All` | 🟠 High | Modify any user account — credential reset |
| `Group.ReadWrite.All` | 🟠 High | Modify group membership — privilege escalation |
| `Files.ReadWrite.All` | 🟠 High | Access all SharePoint/OneDrive files |
| `Sites.ReadWrite.All` | 🟠 High | Full SharePoint site access |
| `SecurityEvents.ReadWrite.All` | 🟡 Medium | Read/modify security alerts — cover tracks |
| `User.Export.All` | 🟡 Medium | Export all user data — bulk exfiltration |
| `Exchange.ManageAsApp` | 🟡 Medium | Full Exchange management — mailbox access |

**Permission risk classification for scoring:**
- **Critical (🔴):** Permissions that enable self-elevation or directory-wide control — 5 permissions listed above
- **High (🟠):** Permissions that enable data access or account manipulation — 8 permissions listed above
- **Medium (🟡):** Permissions that enable reconnaissance or secondary access — 3 permissions listed above

---

## App Permission Risk Score Formula

The App Permission Risk Score is a composite risk indicator summarizing the security posture of your organization's app registration and service principal fleet. Higher scores indicate greater risk.

### Scoring Dimensions

$$
\text{AppPermissionRiskScore} = \sum_{i} \text{DimensionScore}_i
$$

Each dimension contributes 0–20 points to a maximum of 100:

| Dimension | Max | 🟢 Low (0–5) | 🟡 Medium (6–12) | 🔴 High (13–20) |
|-----------|-----|--------------|-------------------|------------------|
| **Permission Concentration** | 20 | 0–2 apps with dangerous perms; 0 critical-tier perms | 3–5 apps with dangerous perms; ≤1 app with ≥3 critical-tier perms | >5 apps with dangerous perms OR ≥2 apps with ≥3 critical-tier perms OR any app with `AppRoleAssignment.ReadWrite.All` (golden ticket → auto 16+) |
| **Owner Risk** | 20 | All flagged apps have admin owners; 0 ownerless dangerous apps | 1–2 ownerless dangerous apps; OR non-admin owner on 🟠-level app | ≥3 ownerless apps with dangerous perms OR non-admin owner on 🔴-level app OR any app owner with active Identity Protection risk (`atRisk`/`confirmedCompromised`) |
| **Credential Hygiene** | 20 | All apps ≤1 active credential; all secrets <180 days old; 0 dormant privileged apps | Any app with 2 active secrets; OR any secret 180d–730d old; OR 1 dormant privileged app | Any app with ≥3 active secrets + critical perms; OR any secret >730d old (2yr); OR cert+secret on same critical app |
| **Cross-Tenant Exposure** | 20 | 0 foreign SPNs with dangerous perms | 1–2 foreign SPNs with 🟠-level perms; all from known/identified partner tenants | Any foreign SPN with 🔴 critical perms (`AppRoleAssignment.ReadWrite.All`, `Directory.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, `Policy.ReadWrite.ConditionalAccess`) OR foreign SPN from unidentified tenant |
| **Active Abuse Signals** | 20 | Q1–Q8 all return 0 non-pipeline results | Q1–Q7 return only 🟡-priority results (after pipeline collapse); OR only `suspiciousAuthAppApproval` self-referencing chains; OR Q8 returns only App Governance “Unused”/“Expiring” alerts with no XDR/MCAS overlap | Q1 returns any chain with `adminConfirmedUserCompromised` or `confirmedCompromised` (→ auto 15+); OR Q6 returns 🔴-priority cred→consent chain from a user with active Identity Protection risk; OR Q8 returns apps with DetectionBreadth ≥2 (multi-source detections) or any Attack Disruption incident |

### Scoring Anchors (Deterministic Rules)

Apply these anchors BEFORE adjusting within bands. They set a floor for the dimension score:

| Condition | Dimension | Minimum Score |
|-----------|-----------|---------------|
| `AppRoleAssignment.ReadWrite.All` granted to ANY app | Permission Concentration | **16** |
| Any app owner has `adminConfirmedUserCompromised` | Owner Risk | **15** |
| Any secret >730 days old on an app with critical perms | Credential Hygiene | **14** |
| Foreign SPN with `AppRoleAssignment.ReadWrite.All` | Cross-Tenant Exposure | **17** |
| Q1 chain with `adminConfirmedUserCompromised` → app consent | Active Abuse Signals | **15** |
| Q8 returns any Attack Disruption incident for an app in Phase 1 | Active Abuse Signals | **16** |
| Q8 returns app with DetectionBreadth ≥3 AND in Phase 1 flagged list | Active Abuse Signals | **14** |
| All Q1–Q8 non-pipeline results = 0 | Active Abuse Signals | **≤5** (cap) |

### Interpretation Scale

| Score | Rating | Action |
|-------|--------|--------|
| **0–20** | ✅ Healthy | Normal posture, routine monitoring |
| **21–45** | 🟡 Elevated | Review — minor permission sprawl or credential age detected |
| **46–70** | 🟠 Concerning | Investigate — multiple risk signals across dimensions |
| **71–100** | 🔴 Critical | Immediate remediation — active abuse chains or critical permission concentration |

---

## Execution Workflow

### Phase 0: Prerequisites

1. Confirm Graph MCP (`mcp_graph-mcp-ser`) is available for posture queries
2. Confirm `RunAdvancedHuntingQuery` is available for chain detection
3. Ask user for output format (inline / markdown / both)
4. Ask user for lookback period (default: 30 days for KQL queries)

### Phase 1: Graph API Posture Inventory (Steps P1–P7)

**Sequential — each step depends on the previous.**

| Step | Purpose | API Call(s) |
|------|---------|-------------|
| P1 | Find Microsoft Graph service principal ID in tenant | 1 call |
| P2 | List ALL application permission grants to Microsoft Graph | 1 call (paginated) — save to `temp/p2_grants.json` |
| P3 | Resolve permission GUIDs to human-readable names | 1 call — **run in parallel with P2** — save to `temp/p3_approles.json` |
| P4 | Filter to dangerous permissions (PowerShell script) | 0 API calls — joins P2+P3 JSON, outputs flagged apps |
| P5 | Resolve owners for flagged apps | N calls (only flagged apps) |
| P6 | Assess owner risk (directory roles) | M calls (only flagged owners) |
| P7 | Credential hygiene check (from P5 response) | 0 calls |

**Total: 3 + N + M calls (typically < 20 for most tenants)**

### Phase 2: KQL Chain Detection (Q1–Q8)

**Run in parallel — no dependencies between queries.** Q8 uses a 90-day lookback (incident data is sparser); Q1–Q7 use 30 days.

| Query | Purpose | Tables | Kill Chain Stage |
|-------|---------|--------|-----------------|
| Q1 | Risky User → App Operations Chain | AADUserRiskEvents + AuditLogs | Compromise → App Abuse |
| Q2 | Credential Add → SPN Activation | AuditLogs + AADServicePrincipalSignInLogs | Persistence → SPN Impersonation |
| Q3 | Ownership Add → Credential Modification Chain | AuditLogs (self-join) | Privilege Escalation → Persistence |
| Q4 | Cross-Tenant SPN Sign-Ins | AADServicePrincipalSignInLogs | Lateral Movement (cross-tenant) |
| Q5 | Credential Add → SPN Graph API Lateral Movement | AuditLogs + MicrosoftGraphActivityLogs | Lateral Movement / Data Exfiltration |
| Q6 | Credential Add → Permission Escalation Chain | AuditLogs (self-join) | Persistence → Privilege Escalation |
| Q7 | Multi-App Ownership Spread | AuditLogs | Persistence (breadth) |
| Q8 | App Governance & OAuth Incident Cross-Reference | AlertInfo + AlertEvidence | Detection Validation |

### Phase 3: Score Computation & Report Generation

1. **Compute per-dimension scores** from Phase 1 and Phase 2 data
2. **Cross-reference:** Map Phase 1 flagged apps to Phase 2 chain detections
3. **Sum dimension scores** for composite App Permission Risk Score
4. **Generate report** in requested output mode
5. **Report total elapsed time**

---

## Phase 1: Graph API Posture Inventory

**Scaling Strategy:** Don't enumerate all app registrations (could be 1000+). Query from the **permission grant side** — find what's been granted dangerous permissions, then resolve owners only for those flagged apps.

### Step P1: Find the Microsoft Graph Service Principal ID

The Microsoft Graph resource service principal is the target of all application permission grants. Its well-known AppId is `00000003-0000-0000-c000-000000000000`, but its ObjectId varies per tenant.

```
GET /v1.0/servicePrincipals?$filter=appId eq '00000003-0000-0000-c000-000000000000'&$select=id,displayName
```

Save the returned `id` — you'll need it for Steps P2 and P3.

### Step P2: List ALL Application Permission Grants to Microsoft Graph

This single call returns every app in the tenant that has been granted **application-level** permissions (not delegated) to Microsoft Graph.

```
GET /v1.0/servicePrincipals/{graph-sp-id}/appRoleAssignedTo
    ?$select=principalDisplayName,principalId,principalType,appRoleId,createdDateTime
    &$top=999
```

**Returns:** One row per permission grant. Each row contains:
- `principalDisplayName` — app name
- `principalId` — ServicePrincipal ObjectId
- `appRoleId` — permission GUID
- `createdDateTime` — when the permission was granted

**Post-processing:** Group by `principalDisplayName` to get the per-app permission list.

**⚠️ Large Response Handling:** P2 can return hundreds of rows (one per permission grant across all apps). When the response is large:

1. **Save P2 and P3 responses to `temp/` as JSON files** before processing — this prevents data loss if context gets truncated
2. **Run P2 and P3 in parallel** — they are independent (P3 only needs the Graph SP ID from P1, same as P2)
3. **Use PowerShell for the GUID→name join and dangerous-permission filter** — do NOT attempt to parse large JSON in-context. Write a script that:
   - Loads P2 grants + P3 appRoles from the saved JSON files
   - Builds the `appRoleId` → `value` lookup map
   - Filters to dangerous permissions
   - Groups by app name
   - Outputs the flagged-app summary (app name, dangerous perms, grant dates, principalId)
4. **Only bring the filtered summary back into context** — the full P2/P3 data stays in temp files for reference

```powershell
# Save MCP responses to temp files first, then:
$grants = Get-Content "temp/p2_grants.json" -Raw | ConvertFrom-Json
$roles = Get-Content "temp/p3_approles.json" -Raw | ConvertFrom-Json

# Build GUID→name map
$roleMap = @{}
foreach ($r in $roles) { $roleMap[$r.id] = $r.value }

# Dangerous permissions list
$dangerousPerms = @(
    "Directory.ReadWrite.All", "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All", "RoleManagement.ReadWrite.Directory",
    "Mail.ReadWrite", "Mail.Send", "Mail.Read",
    "Files.ReadWrite.All", "User.ReadWrite.All", "Group.ReadWrite.All",
    "Sites.ReadWrite.All", "MailboxSettings.ReadWrite", "User.Export.All",
    "Exchange.ManageAsApp", "full_access_as_app",
    "Policy.ReadWrite.ConditionalAccess", "SecurityEvents.ReadWrite.All"
)

# Enrich grants with permission names and filter
$enriched = $grants | ForEach-Object {
    $permName = $roleMap[$_.appRoleId]
    [PSCustomObject]@{
        App = $_.principalDisplayName
        PrincipalId = $_.principalId
        Permission = $permName
        Dangerous = $permName -in $dangerousPerms
        GrantDate = $_.createdDateTime
    }
}

# Summary: apps with dangerous permissions
$flagged = $enriched | Where-Object Dangerous | Group-Object App | ForEach-Object {
    [PSCustomObject]@{
        App = $_.Name
        DangerousPerms = ($_.Group.Permission | Sort-Object -Unique) -join ", "
        Count = $_.Count
        LatestGrant = ($_.Group.GrantDate | Sort-Object -Descending | Select-Object -First 1)
        PrincipalId = $_.Group[0].PrincipalId
    }
} | Sort-Object Count -Descending

# Display summary
$totalApps = ($enriched | Select-Object -Unique App).Count
Write-Host "Total apps with Graph permissions: $totalApps"
Write-Host "Apps with dangerous permissions: $($flagged.Count)"
Write-Host "Total dangerous grants: $(($enriched | Where-Object Dangerous).Count)"
$flagged | Format-Table -AutoSize
```

This script replaces the manual P3/P4 steps — it does the GUID resolution AND dangerous-permission filtering in one pass.

### Step P3: Resolve Permission GUIDs to Names

**Run in parallel with P2** — both only need the Graph SP ID from P1.

```
GET /v1.0/servicePrincipals/{graph-sp-id}/appRoles
```

**Returns:** Complete list of Microsoft Graph permission definitions with `id` (GUID), `value` (e.g., `Mail.ReadWrite`), and `displayName`.

Save the response to `temp/p3_approles.json`. The PowerShell script from P2 loads this file to build the GUID→name lookup.

### Step P4: Filter to Dangerous Permissions

**Handled by the PowerShell script in P2.** The script performs GUID→name join, dangerous-permission filter, and per-app grouping in one pass. No additional API calls needed.

**Output:** A table of flagged apps with their dangerous permission list, permission risk level, and grant dates.

### Step P5: Resolve Owners for Flagged Apps

**Only** for apps flagged in P4, retrieve owners from the **Application object** (NOT the ServicePrincipal):

```
GET /v1.0/applications?$filter=displayName eq '{flagged-app-name}'
    &$select=id,appId,displayName,passwordCredentials,keyCredentials
    &$expand=owners($select=id,displayName,userPrincipalName)
```

Repeat for each flagged app. **Important:**
- Cross-tenant SPNs return empty results (no local Application object)
- Red team apps may have owners stripped post-creation
- For ownerless apps, fall back to AuditLogs `"Add application"` to find original creator

### Step P6: Assess Owner Risk

For each owner found in P5:

1. **Check directory roles** — is the owner a privileged admin or a standard user?
   ```
   GET /v1.0/roleManagement/directory/roleAssignments
       ?$filter=principalId eq '{owner-id}'
       &$expand=roleDefinition($select=displayName)
   ```
   Non-admin owners of apps with critical permissions = the Guardz attack vector.

2. **Check Identity Protection risk** — feed `owner.userPrincipalName` into Q1 to detect active risk events. An owner currently flagged by Identity Protection who owns a dangerous app is the highest-priority finding.

### Step P7: Credential Hygiene Check

The P5 response includes `passwordCredentials` and `keyCredentials`. Assess:

| Check | Field | Risk |
|-------|-------|------|
| Multiple active secrets | `passwordCredentials[]` where `endDateTime > now` | 🟠 Multiple access methods — harder to revoke |
| Long-lived secrets | `endDateTime` > 2 years from `startDateTime` | 🟠 Stale credential risk — may leak without detection |
| No credentials at all | Empty `passwordCredentials` + `keyCredentials` | 🟢 App can't be used for SPN auth (lower risk) |
| Certificate + Secret both active | Both arrays non-empty | 🟡 Review — cert is expected, secret alongside is unusual |

---

## Phase 2: KQL Chain Detection Queries

> **All queries below are verified against live data. Use them exactly as written, substituting only the lookback period and chain windows where noted.**
>
> **Tool:** Use `RunAdvancedHuntingQuery` for all queries. All tables are Analytics-tier — AH queries are free. Fall back to `mcp_sentinel-data_query_lake` only for lookback > 30 days.

### Query 1: Risky User → App Operations Chain (HIGHEST SIGNAL)

**Purpose:** Detect users with active Identity Protection risk detections who then perform app credential, ownership, or consent operations.

**Kill Chain Stage:** Compromise → App Abuse

**Tables:** `AADUserRiskEvents` + `AuditLogs`

**Why high signal:** A user flagged by Identity Protection performing app credential operations within days is strong evidence of the exact attack pattern described in the Guardz research.

```kql
// Chain Detection: Users with active risk → app credential/ownership operations
let lookback = 30d;
let chainWindow = 7d; // Risk event → app operation within 7 days
// Step 1: Users with unresolved or confirmed risk
let RiskyUsers = AADUserRiskEvents
| where TimeGenerated > ago(lookback)
| where RiskState in ("atRisk", "confirmedCompromised")
| summarize 
    RiskEvents = count(),
    RiskTypes = make_set(RiskEventType, 5),
    MaxRiskLevel = max(RiskLevel),
    EarliestRisk = min(TimeGenerated),
    LatestRisk = max(TimeGenerated)
    by UserPrincipalName;
// Step 2: App credential/ownership/consent operations by those users
AuditLogs
| where TimeGenerated > ago(lookback)
| where Category == "ApplicationManagement"
| where OperationName has_any ("credential", "secret", "certificate", "owner", "consent", "permission")
| extend InitiatedByUser = tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName)
| where isnotempty(InitiatedByUser)
| extend Target = parse_json(tostring(TargetResources))[0]
| extend TargetAppName = coalesce(
    tostring(Target.displayName),
    tostring(parse_json(tostring(parse_json(tostring(Target.modifiedProperties))[1].newValue))))
| join kind=inner RiskyUsers on $left.InitiatedByUser == $right.UserPrincipalName
| where TimeGenerated between (EarliestRisk .. (LatestRisk + chainWindow))
| project 
    RiskDetectedAt = EarliestRisk,
    AppOperationAt = TimeGenerated,
    TimeDeltaHours = datetime_diff('hour', TimeGenerated, EarliestRisk),
    User = InitiatedByUser,
    RiskTypes,
    MaxRiskLevel,
    RiskEvents,
    OperationName,
    TargetApp = TargetAppName,
    CorrelationId
| order by RiskDetectedAt desc
```

**Triage Priority:**
- 🔴 **Critical:** `MaxRiskLevel` = high + credential add operation → likely active compromise
- 🟠 **High:** `MaxRiskLevel` = medium + ownership add → attacker positioning for persistence
- 🟡 **Medium:** `MaxRiskLevel` = low + consent grant → may be `suspiciousAuthAppApproval` self-referencing

**Tuning:**
- Tighten `chainWindow` to `1d` for higher precision
- Add `| where RiskTypes !has "suspiciousAuthAppApproval"` to exclude consent-flagging-consent loops

### Query 2: Credential Add → SPN Activation from New Origin

**Purpose:** After a credential is added to an app, detect when the SPN authenticates from a new IP within 72 hours. This is the SolarWinds "backdoor credential → authenticate as the app" pattern.

**Kill Chain Stage:** Persistence → SPN Impersonation

**Tables:** `AuditLogs` + `AADServicePrincipalSignInLogs`

```kql
// Chain Detection: Credential added → SPN signs in within 72h
let lookback = 30d;
let activationWindow = 72h;
// Step 1: Credential additions with actor and target
let CredentialAdds = AuditLogs
| where TimeGenerated > ago(lookback)
| where Category == "ApplicationManagement"
| where OperationName in~ (
    "Update application – Certificates and secrets management ",
    "Add service principal credentials"
  )
| extend InitiatedByUser = tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName)
| extend InitiatedByApp = tostring(parse_json(tostring(InitiatedBy)).app.displayName)
| extend Actor = iff(isnotempty(InitiatedByUser), InitiatedByUser, InitiatedByApp)
| extend Target = parse_json(tostring(TargetResources))[0]
| extend TargetAppName = tostring(Target.displayName)
| extend TargetAppId = tostring(Target.id)
| extend ModifiedProps = parse_json(tostring(Target.modifiedProperties))
| extend KeyDescription = tostring(ModifiedProps[0].newValue)
| extend CredentialType = case(
    KeyDescription has "AsymmetricX509Cert", "Certificate",
    KeyDescription has "Password", "Client Secret",
    "Unknown")
| project CredAddTime = TimeGenerated, Actor, TargetAppName, TargetAppId, CredentialType, CorrelationId;
// Step 2: SPN sign-ins after credential add
CredentialAdds
| join kind=inner (
    AADServicePrincipalSignInLogs
    | where TimeGenerated > ago(lookback)
    | where ResultType == "0" // successful only
    | project SPNSignInTime = TimeGenerated, AppId, ServicePrincipalName, IPAddress, 
        Location, ResourceDisplayName, ClientCredentialType,
        ServicePrincipalCredentialKeyId
) on $left.TargetAppId == $right.AppId
| where SPNSignInTime between (CredAddTime .. (CredAddTime + activationWindow))
| summarize
    SPNSignIns = count(),
    DistinctIPs = dcount(IPAddress),
    IPs = make_set(IPAddress, 10),
    Resources = make_set(ResourceDisplayName, 5),
    CredTypes = make_set(ClientCredentialType, 5),
    FirstSignIn = min(SPNSignInTime),
    LastSignIn = max(SPNSignInTime)
    by CredAddTime, Actor, TargetAppName, TargetAppId, CredentialType, CorrelationId
| extend HoursToActivation = datetime_diff('hour', FirstSignIn, CredAddTime)
| order by CredAddTime desc
```

**Triage Priority:**
- 🔴 **Critical:** `HoursToActivation` < 1 + new IP not in SPN's historical baseline
- 🟠 **High:** `HoursToActivation` < 24 + accessing sensitive resources (Graph, Key Vault)
- 🟡 **Medium:** Normal activation window but from multiple IPs

**Enhancement:** Run the SPN scope drift skill (`.github/skills/scope-drift-detection/spn/SKILL.md`) on any flagged SPN for baseline comparison.

### Query 3: Ownership Add → Credential Modification Chain

**Purpose:** Detect the exact Guardz attack sequence — user is added as app owner, then credentials are modified on that app within 7 days. The `SameActorAsNewOwner` flag is key: if the newly added owner immediately creates a credential, that's the attacker using ownership to establish persistence.

**Kill Chain Stage:** Privilege Escalation → Persistence

**Tables:** `AuditLogs` (self-join)

```kql
// Chain Detection: Owner added to app → credential/permission op on same app within 7d
let lookback = 30d;
let chainWindow = 7d;
// Step 1: Ownership additions — extract new owner and target app
let OwnershipAdds = AuditLogs
| where TimeGenerated > ago(lookback)
| where Category == "ApplicationManagement"
| where OperationName in~ ("Add owner to application", "Add owner to service principal")
| extend Target0 = parse_json(tostring(TargetResources))[0]
| extend NewOwnerUPN = tostring(Target0.userPrincipalName)
| extend NewOwnerId = tostring(Target0.id)
| extend ModProps = parse_json(tostring(Target0.modifiedProperties))
| extend TargetAppName = tostring(parse_json(tostring(ModProps[1].newValue)))
| extend TargetAppId = tostring(parse_json(tostring(ModProps[0].newValue)))
| extend InitiatedByUser = tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName)
| extend Actor = iff(isnotempty(InitiatedByUser), InitiatedByUser, tostring(parse_json(tostring(InitiatedBy)).app.displayName))
| project OwnerAddTime = TimeGenerated, Actor, NewOwnerUPN, TargetAppName, TargetAppId, OperationName;
// Step 2: Credential or permission operations on the same app
AuditLogs
| where TimeGenerated > ago(lookback)
| where Category == "ApplicationManagement"
| where OperationName in~ (
    "Update application – Certificates and secrets management ",
    "Add service principal credentials",
    "Add delegated permission grant",
    "Consent to application",
    "Add app role assignment to service principal"
  )
| extend Target = parse_json(tostring(TargetResources))[0]
| extend CredTargetId = tostring(Target.id)
| extend CredActor = tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName)
| join kind=inner OwnershipAdds on $left.CredTargetId == $right.TargetAppId
| where TimeGenerated between (OwnerAddTime .. (OwnerAddTime + chainWindow))
| project
    OwnerAddTime,
    CredOpTime = TimeGenerated,
    HoursGap = datetime_diff('hour', TimeGenerated, OwnerAddTime),
    NewOwnerUPN,
    CredActor,
    SameActorAsNewOwner = (CredActor =~ NewOwnerUPN),
    OwnershipOp = OperationName1,
    CredentialOp = OperationName,
    TargetAppName,
    TargetAppId
| order by OwnerAddTime desc
```

**Triage Priority:**
- 🔴 **Critical:** `SameActorAsNewOwner` = true + `HoursGap` < 1 → scripted attack
- 🟠 **High:** `SameActorAsNewOwner` = true + `HoursGap` < 24 → manual attacker
- 🟡 **Medium:** Different actors (admin added owner, owner later legitimately rotated creds)

### Query 4: SPN Cross-Tenant Sign-Ins

**Purpose:** Detect service principals owned by external tenants authenticating into your tenant. Multi-tenant app abuse was the core SolarWinds persistence mechanism.

**Kill Chain Stage:** Lateral Movement (cross-tenant)

**Tables:** `AADServicePrincipalSignInLogs`

```kql
// Detect cross-tenant SPN authentication — foreign SPNs accessing local resources
AADServicePrincipalSignInLogs
| where TimeGenerated > ago(30d)
| where ResultType == "0"
| where isnotempty(AppOwnerTenantId)
| where AppOwnerTenantId != AADTenantId
| summarize 
    SignIns = count(),
    DistinctIPs = dcount(IPAddress),
    IPs = make_set(IPAddress, 5),
    Resources = make_set(ResourceDisplayName, 10),
    CredTypes = make_set(ClientCredentialType, 5),
    Locations = make_set(Location, 5),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by ServicePrincipalName, AppId, AppOwnerTenantId, AADTenantId
| order by SignIns desc
```

**Triage Priority:**
- 🔴 **Critical:** Unknown foreign tenant SPN accessing sensitive resources (Graph, Key Vault, ARM)
- 🟠 **High:** Known partner/vendor SPN with new access patterns
- 🟡 **Low:** Microsoft first-party service SPNs (verify against [first-party app list](https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/governance/verify-first-party-apps-sign-in))

**Enhancement — New Cross-Tenant SPNs (first seen in last 7d vs 30d baseline):**

```kql
let recent = 7d;
let baseline = 30d;
let RecentCrossTenant = AADServicePrincipalSignInLogs
| where TimeGenerated > ago(recent)
| where ResultType == "0"
| where AppOwnerTenantId != AADTenantId
| distinct AppId, ServicePrincipalName, AppOwnerTenantId;
let BaselineCrossTenant = AADServicePrincipalSignInLogs
| where TimeGenerated between (ago(baseline) .. ago(recent))
| where ResultType == "0"
| where AppOwnerTenantId != AADTenantId
| distinct AppId;
RecentCrossTenant
| join kind=leftanti BaselineCrossTenant on AppId
| project ServicePrincipalName, AppId, AppOwnerTenantId
```

### Query 5: Credential Add → SPN Graph API Lateral Movement

**Purpose:** After a credential is added, track what Graph API calls the SPN makes. Categorizes API endpoints into sensitive categories to identify lateral movement and data exfiltration.

**Kill Chain Stage:** Lateral Movement / Data Exfiltration

**Tables:** `AuditLogs` + `MicrosoftGraphActivityLogs`

**Prerequisite:** `MicrosoftGraphActivityLogs` must be ingested (requires Entra ID P1/P2 + diagnostic settings enabled).

```kql
// Chain Detection: Credential added → SPN Graph API calls within 72h
let lookback = 30d;
let monitorWindow = 72h;
// Step 1: Apps that had credentials added
let CredentialAdds = AuditLogs
| where TimeGenerated > ago(lookback)
| where Category == "ApplicationManagement"
| where OperationName in~ (
    "Update application – Certificates and secrets management ",
    "Add service principal credentials"
  )
| extend Target = parse_json(tostring(TargetResources))[0]
| extend TargetAppId = tostring(Target.id)
| extend TargetAppName = tostring(Target.displayName)
| extend Actor = tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName)
| project CredAddTime = TimeGenerated, Actor, TargetAppName, TargetAppId;
// Step 2: Graph API calls by those apps after credential add
CredentialAdds
| join kind=inner (
    MicrosoftGraphActivityLogs
    | where TimeGenerated > ago(lookback)
    | where isnotempty(ServicePrincipalId)
    | project GraphCallTime = TimeGenerated, AppId, RequestMethod, RequestUri, 
        ResponseStatusCode, ServicePrincipalId
) on $left.TargetAppId == $right.AppId
| where GraphCallTime between (CredAddTime .. (CredAddTime + monitorWindow))
| extend EndpointCategory = case(
    RequestUri has "/roleManagement/", "Role Management",
    RequestUri has_any ("/applications/", "/servicePrincipals/"), "App/SPN Management",
    RequestUri has "/users/", "User Enumeration",
    RequestUri has "/groups/", "Group Enumeration",
    RequestUri has "/identity/conditionalAccess/", "CA Policy Access",
    RequestUri has "/policies/", "Policy Management",
    RequestUri has "/security/", "Security Data",
    RequestUri has_any ("/mail/", "/messages", "/mailFolders"), "Email Access",
    RequestUri has_any ("/drives/", "/sites/"), "File Access",
    RequestUri has "/auditLogs/", "Audit Log Access",
    "Other")
| where EndpointCategory != "Other"
| summarize 
    GraphCalls = count(),
    Methods = make_set(RequestMethod, 5),
    SampleUris = make_set(RequestUri, 3),
    SuccessRate = round(100.0 * countif(ResponseStatusCode >= 200 and ResponseStatusCode < 300) / count(), 1)
    by CredAddTime, Actor, TargetAppName, TargetAppId, EndpointCategory
| order by CredAddTime desc, GraphCalls desc
```

**Triage Priority:**
- 🔴 **Critical:** `Role Management` or `App/SPN Management` → privilege escalation / further persistence
- 🔴 **Critical:** `Email Access` → data exfiltration (SolarWinds primary objective)
- 🟠 **High:** `CA Policy Access` or `Policy Management` → defense evasion
- 🟡 **Medium:** `File Access` → potential data staging

### Query 6: Credential Add → Permission Escalation Chain

**Purpose:** After adding a credential (persistence), detect the attacker granting additional permissions or consenting to broader API access on the same app.

**Kill Chain Stage:** Persistence → Privilege Escalation

**Tables:** `AuditLogs` (self-join)

**Schema Note:** Credential operations and consent operations use different ID spaces for the same app (Application ObjectId vs ServicePrincipal ObjectId). This query joins on `Actor` + `TargetAppName` to bridge the gap.

```kql
// Chain Detection: Credential added → permission/consent on same app within 7d
let lookback = 30d;
let escalationWindow = 7d;
// Step 1: Credential additions
let CredentialAdds = AuditLogs
| where TimeGenerated > ago(lookback)
| where Category == "ApplicationManagement"
| where OperationName in~ (
    "Update application – Certificates and secrets management ",
    "Add service principal credentials"
  )
| extend Target = parse_json(tostring(TargetResources))[0]
| extend TargetAppName = tostring(Target.displayName)
| where isnotempty(TargetAppName)
| extend CredActor = tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName)
| where isnotempty(CredActor)
| project CredAddTime = TimeGenerated, CredActor, TargetAppName;
// Step 2: Permission grants by same actor on same-named app
let PermissionGrants = AuditLogs
| where TimeGenerated > ago(lookback)
| where Category == "ApplicationManagement"
| where OperationName in~ (
    "Add delegated permission grant",
    "Consent to application",
    "Add app role assignment to service principal"
  )
| extend EscActor = tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName)
| where isnotempty(EscActor)
| extend Target0 = parse_json(tostring(TargetResources))[0]
| extend PermAppName = case(
    OperationName =~ "Consent to application", tostring(Target0.displayName),
    tostring(Target0.displayName))
| project PermOpTime = TimeGenerated, EscActor, PermAppName, EscalationOp = OperationName;
// Join: same actor + same app + credential first then permission
CredentialAdds
| join kind=inner PermissionGrants on $left.CredActor == $right.EscActor, $left.TargetAppName == $right.PermAppName
| where PermOpTime between (CredAddTime .. (CredAddTime + escalationWindow))
| project
    CredAddTime,
    PermissionOpTime = PermOpTime,
    HoursGap = datetime_diff('hour', PermOpTime, CredAddTime),
    Actor = CredActor,
    TargetAppName,
    EscalationOp
| order by CredAddTime desc
```

**Triage Priority:**
- 🔴 **Critical:** `HoursGap` = 0 + consent grant → automated attack tool
- 🟠 **High:** Consent to powerful API scopes
- 🟡 **Medium:** `Add app role assignment` with larger gap → possibly legitimate

### Query 7: Multi-App Ownership Spread

**Purpose:** Detect a single user being added as owner to multiple applications within a rolling window. Attackers spread ownership across apps to maximize blast radius.

**Kill Chain Stage:** Persistence (breadth)

**Tables:** `AuditLogs`

```kql
// Detect lateral ownership expansion — one user becoming owner of many apps
let lookback = 30d;
AuditLogs
| where TimeGenerated > ago(lookback)
| where Category == "ApplicationManagement"
| where OperationName in~ ("Add owner to application", "Add owner to service principal")
| extend Target0 = parse_json(tostring(TargetResources))[0]
| extend NewOwnerUPN = tostring(Target0.userPrincipalName)
| extend ModProps = parse_json(tostring(Target0.modifiedProperties))
| extend TargetAppName = tostring(parse_json(tostring(ModProps[1].newValue)))
| extend TargetAppId = tostring(parse_json(tostring(ModProps[0].newValue)))
| extend InitiatedByUser = tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName)
| extend Actor = iff(isnotempty(InitiatedByUser), InitiatedByUser, tostring(parse_json(tostring(InitiatedBy)).app.displayName))
| where isnotempty(NewOwnerUPN)
| summarize
    AppsOwned = dcount(TargetAppId),
    AppNames = make_set(TargetAppName, 10),
    OwnershipOps = count(),
    FirstAdd = min(TimeGenerated),
    LastAdd = max(TimeGenerated),
    AddedBy = make_set(Actor, 5)
    by NewOwnerUPN
| extend SpreadWindowHours = datetime_diff('hour', LastAdd, FirstAdd)
| where AppsOwned >= 3
| order by AppsOwned desc
```

**Triage Priority:**
- 🔴 **Critical:** `AppsOwned` >= 5 + `SpreadWindowHours` < 24 → bulk automated ownership grab
- 🟠 **High:** Non-admin user (`AddedBy` = themselves) with `AppsOwned` >= 3
- 🟡 **Medium:** Automation account adding ownership as part of deployment

**Enhancement:** Feed `NewOwnerUPN` values into Q1 to check for active identity risk events.

### Query 8: App Governance & OAuth Incident Cross-Reference

**Purpose:** Surface existing Defender detections (App Governance, MCAS, Defender XDR attack disruptions) for apps in our posture assessment. Creates a cross-reference between our Graph API + KQL findings and what Microsoft's own detection products already flagged — confirming known threats and highlighting gaps.

**Kill Chain Stage:** Detection Validation (cross-reference)

**Tables:** `AlertInfo` + `AlertEvidence`

**Why this matters:**
- Apps flagged by BOTH our skill AND App Governance/XDR → confirmed threat, urgent remediation
- Apps flagged ONLY by our skill → unique detection value (the skill caught what App Governance missed)
- Apps flagged ONLY by App Governance → coverage gap in our assessment (e.g., apps without dangerous Graph perms but with suspicious behavior)

**Key field mappings (discovered via live testing):**

| Field | Table | Values |
|-------|-------|--------|
| `ServiceSource` | `AlertInfo` | `"App Governance"`, `"Microsoft Defender for Cloud Apps"`, `"Microsoft Defender XDR"`, `"Microsoft Defender for Identity"` |
| `DetectionSource` | `AlertInfo` | `"App Governance Policy"`, `"Microsoft 365 Defender"`, `"Security Copilot"`, `"Custom detection"` |
| `EntityType` | `AlertEvidence` | `"OAuthApplication"` (app entities), `"CloudApplication"` (resource targets) |
| `AdditionalFields.OAuthAppId` | `AlertEvidence` | Application (client) ID — join key to Graph API flagged apps |
| `AdditionalFields.Name` | `AlertEvidence` | App display name |

**App Governance alert types:**
- `Custom policy`, `App Creation Policy` — admin-defined rules
- `Overprivileged app`, `New highly privileged app` — permission-based detections
- `Expiring credentials`, `Unused credentials`, `Unused app` — hygiene alerts

**Defender XDR OAuth alert types:**
- `Malicious OAuth application registration by a compromised user` — attack disruption
- `Suspicious OAuth consent and privilege escalation activity` — Security Copilot detection
- `Suspicious OAuth app registration` — MCAS detection
- `Anomalous OAuth device code authentication activity` — MDI detection

```kql
// Q8: App Governance + OAuth Incident Cross-Reference
let lookback = 90d;
// Part 1: App Governance alerts
let AppGovAlerts = AlertInfo
| where Timestamp > ago(lookback)
| where ServiceSource == "App Governance"
| project AlertId, AlertTitle = Title, ServiceSource, DetectionSource, Severity, Timestamp;
// Part 2: OAuth-related alerts from all sources
let OAuthAlerts = AlertInfo
| where Timestamp > ago(lookback)
| where Title has "OAuth"
    or (ServiceSource == "Microsoft Defender for Cloud Apps" and Title has_any ("app registration", "OAuth"))
| project AlertId, AlertTitle = Title, ServiceSource, DetectionSource, Severity, Timestamp;
// Part 3: Attack Disruption incidents targeting OAuth/compromised-user app abuse
let AttackDisruption = AlertInfo
| where Timestamp > ago(lookback)
| where Title has "attack disruption" and Title has_any ("OAuth", "malicious", "compromised")
| project AlertId, AlertTitle = Title, ServiceSource, DetectionSource, Severity, Timestamp;
// Combine all alert sources (deduplicate)
let AllAppAlerts = union AppGovAlerts, OAuthAlerts, AttackDisruption
| summarize arg_max(Timestamp, *) by AlertId;
// Join with AlertEvidence to get OAuthApplication entities
AllAppAlerts
| join kind=leftouter (
    AlertEvidence
    | where Timestamp > ago(lookback)
    | where EntityType == "OAuthApplication"
    | extend OAuthAppId = tostring(parse_json(AdditionalFields).OAuthAppId)
    | extend OAuthAppName = tostring(parse_json(AdditionalFields).Name)
    | project AlertId, OAuthAppId, OAuthAppName, EntityType
) on AlertId
| summarize
    AlertCount = count(),
    AlertTitles = make_set(AlertTitle, 10),
    Severities = make_set(Severity, 5),
    ServiceSources = make_set(ServiceSource, 5),
    DetectionSources = make_set(DetectionSource, 5),
    LatestAlert = max(Timestamp),
    EarliestAlert = min(Timestamp)
    by OAuthAppName, OAuthAppId
| extend OAuthAppName = iff(isempty(OAuthAppName), "⚠️ No app entity extracted", OAuthAppName)
| extend HasDefenderXDR = ServiceSources has "Microsoft Defender XDR"
| extend HasAppGov = ServiceSources has "App Governance"
| extend HasMCAS = ServiceSources has "Microsoft Defender for Cloud Apps"
| extend DetectionBreadth = toint(HasDefenderXDR) + toint(HasAppGov) + toint(HasMCAS)
| order by DetectionBreadth desc, AlertCount desc
```

**Post-processing — Cross-reference with Phase 1 flagged apps:**

After Q8 returns, compare the `OAuthAppName` values against the apps flagged in Phase 1 (P4):

| Scenario | Meaning | Report Action |
|----------|---------|---------------|
| App in **BOTH** Phase 1 (dangerous perms) AND Q8 (existing detections) | Confirmed threat — multiple detection layers agree | 🔴 Highlight in report: "Corroborated by N existing Defender detections" |
| App in Phase 1 **ONLY** (dangerous perms, no Q8 hits) | Skill-unique detection — App Governance hasn't flagged it | 🟠 Highlight: "Not yet detected by App Governance — unique skill finding" |
| App in Q8 **ONLY** (existing detections, not in Phase 1) | App may not have dangerous Graph perms but has suspicious behavior | 🔵 Include in appendix: "Additional apps flagged by App Governance (not in dangerous-perms scope)" |
| App with `DetectionBreadth` ≥ 2 | Multiple Defender products independently detected the app | 🔴 Highest confidence finding |

**Triage Priority:**
- 🔴 **Critical:** `DetectionBreadth` ≥ 2 AND app also in Phase 1 flagged list → multi-source confirmed threat
- 🔴 **Critical:** Any alert titled "Malicious OAuth application registration by a compromised user" (attack disruption) → Defender XDR auto-disrupted the attack
- 🟠 **High:** App Governance `Overprivileged app` or `New highly privileged app` alerts on Phase 1 flagged apps
- 🟡 **Medium:** App Governance hygiene alerts (`Expiring credentials`, `Unused app`) on any app

---

## Output Modes

### Mode 1: Inline Chat Summary

Render the full analysis directly in the chat response. Best for quick review.

### Mode 2: Markdown File Report

Save a comprehensive report to disk at:
```
reports/app-registration-posture/App_Registration_Posture_Report_{tenant}_YYYYMMDD_HHMMSS.md
```

Where `{tenant}` is a short identifier for the tenant (derive from `config.json` or ask the user).

### Mode 3: Both

Generate the markdown file AND provide an inline summary in chat.

**Always ask the user which mode before generating output.**

---

## Inline Report Template

Render the following sections in order. Omit sections only if explicitly noted as conditional.

> **🔴 URL Rule:** All hyperlinks in the report MUST be copied verbatim from the [URL Registry](#-url-registry--canonical-links-for-report-generation) above. Do NOT generate, recall from memory, or paraphrase any URL. If a needed URL is not in the registry, use plain text (no hyperlink).

````markdown
# 🔐 App Registration Security Posture Report

**Generated:** YYYY-MM-DD HH:MM UTC  
**Data Sources:** Graph API + Advanced Hunting (AuditLogs, AADServicePrincipalSignInLogs, AADUserRiskEvents, MicrosoftGraphActivityLogs, AlertInfo, AlertEvidence)  
**KQL Lookback:** <N> days (Q1–Q7); 90 days (Q8)  
**Tenant:** <tenant name> (<tenant ID>)

---

## Executive Summary

<2-3 sentences: total apps with Graph permissions, apps with dangerous permissions, key chain detection findings, overall score>

**Overall Risk Rating:** 🔴/🟠/🟡/✅ <RATING> (<Score>/100)

---

## Key Metrics

| Metric | Value |
|--------|-------|
| Apps with Graph API Permissions | <N> |
| Apps with Dangerous Permissions | <N> |
| Critical Permission Grants (🔴) | <N> |
| High Permission Grants (🟠) | <N> |
| Medium Permission Grants (🟡) | <N> |
| Ownerless Apps with Dangerous Perms | <N> |
| Apps with No Local Application Object | <N> |
| Cross-Tenant SPNs | <N> |
| Active Abuse Chain Detections (Q1–Q8) | <N total hits> |

---

## 🔐 Permission Inventory (Graph API)

### Apps with Dangerous Permissions

| App Name | Dangerous Permissions | Risk Level | Grant Dates |
|----------|----------------------|------------|-------------|
| <app> | <perm1>, <perm2>, ... | 🔴/🟠/🟡 | <dates> |

### Permission Concentration

| Permission | Apps Granted | Risk |
|------------|-------------|------|
| <perm> | <N> (<app names>) | 🔴/🟠/🟡 |

**Assessment:**
- <emoji> <evidence-based finding about permission concentration>
- <emoji> <finding about golden ticket permissions (AppRoleAssignment.ReadWrite.All)>

---

## 👤 Owner Risk Assessment

### Flagged App Owners

> **Non-optional columns:** The `Identity Protection Risk` column MUST always be present. For each owner, check Q1 results or query AADUserRiskEvents for active risk state. If no risk events exist, show "✅ None". Never drop this column.

| App Name | Owner | Owner Roles | Identity Protection Risk | Owner Risk |
|----------|-------|-------------|--------------------------|------------|
| <app> | <upn> | <roles or "None (standard user)"> | <risk state + risk types, or "✅ None"> | 🔴/🟠/🟡/🟢 |

### Ownerless Apps with Dangerous Permissions

| App Name | Dangerous Permissions | Creator (from AuditLogs) |
|----------|----------------------|--------------------------|
| <app> | <perms> | <creator UPN or "Unknown"> |

**Assessment:**
- <emoji> <finding about non-admin owners on critical-permission apps>
- <emoji> <finding about ownerless apps>

---

## 🔑 Credential Hygiene

| App Name | Active Secrets | Active Certs | Oldest Secret Age | Longest Expiry | Risk |
|----------|---------------|-------------|-------------------|----------------|------|
| <app> | <N> | <N> | <days> | <date> | 🔴/🟠/🟡/🟢 |

**Assessment:**
- <emoji> <finding about multi-credential apps>
- <emoji> <finding about long-lived secrets>
- 🟡 **Dormant privileged apps:** List any apps with dangerous permissions but NO active credentials (0 secrets, 0 valid certs). These are one `Add service principal credentials` operation away from active abuse — rate as 🟡 at assessment level (not 🟢). Example: "Contoso employee onboarding has `User.ReadWrite.All` but no credentials — dormant risk."

---

## 🌐 Cross-Tenant SPN Exposure (Q4)

<If Q4 returns results:>
| SPN Name | Owner Tenant | Sign-Ins (30d) | Distinct IPs | Resources Accessed | Auth Methods | Locations | First Seen | Last Seen |
|----------|-------------|----------------|-------------|-------------------|-------------|-----------|------------|-----------|
| <name> | <tenant ID> | <N> | <N> | <resources> | <methods> | <locations> | <date> | <date> |

> **Auth method note:** `clientAssertion` (certificate-based) indicates higher attacker sophistication than `clientSecret`. Both present on a single SPN may indicate migration or redundant credential paths.

<If Q4 enhancement returns new SPNs:>
⚠️ **New Cross-Tenant SPNs (first seen in last 7 days):**
| SPN Name | Owner Tenant |
|----------|-------------|
| <name> | <tenant ID> |

<If Q4 returns 0:>
✅ No cross-tenant SPN sign-ins detected in the last <N> days.

**Assessment:**
- <emoji> <finding about foreign-tenant SPNs with golden ticket or CA policy write permissions>
- <emoji> <finding about sign-in volume and resource breadth>
- 🔵 Filter out known [first-party Microsoft service SPNs](https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/governance/verify-first-party-apps-sign-in) — normal behavior.

---

## ⚡ Active Abuse Chain Detection (Q1–Q3, Q5–Q8)

> **Note:** Q4 (Cross-Tenant SPNs) is presented in its own section above since it doubles as both a chain detection and a posture finding.

> **Bulk-pattern collapse rule:** When any chain query (Q1–Q8) returns >10 chains where >80% share the same actor AND the same pattern (uniform resource, timing, app naming convention), collapse into a single **"Automated Pipeline"** summary row with the total count and a governance-review flag. Only table the outliers individually. This prevents automation noise from burying genuine attack chains.

### Q1: Risky User → App Operations

<If Q1 returns results, always start with a rollup summary table:>

**Summary:**
| Priority | Chains | Users | Key Finding |
|----------|--------|-------|-------------|
| 🔴 Critical | <N> | <users> | <top finding — e.g., adminConfirmedUserCompromised → app consent> |
| 🟠 High | <N> | <users> | <summary> |
| 🟡 Low | <N> | <users> | <summary or "consent-flagging-consent loops"> |

<Then detail tables for 🔴 Critical and 🟠 High chains only. Collapse 🟡 Low into the summary.>

| Risk Detected | App Operation | Hours Gap | User | Risk Types | Risk Level | Target App |
|--------------|---------------|-----------|------|------------|------------|------------|
| <date> | <date> | <N> | <upn> | <types> | <level> | <app> |

> ⚠️ **Self-referencing note:** If Q1 results are dominated by `suspiciousAuthAppApproval` risk types, these may be self-referencing — Identity Protection flags consent operations as risky, which then correlates back to the same consent. Report both the raw count and a filtered count (`| where RiskTypes !has "suspiciousAuthAppApproval"`) to distinguish genuine compromise signals from circular detections.

<If Q1 returns 0:>
✅ No risky-user → app-operations chains detected.

### Q2: Credential Add → SPN Activation

<If Q2 returns results:>
| Cred Added | First SPN Sign-In | Hours to Activation | Actor | App | Distinct IPs | Resources |
|------------|-------------------|---------------------|-------|-----|-------------|-----------|
| <date> | <date> | <N> | <upn> | <app> | <N> | <resources> |

<If Q2 returns 0:>
✅ No credential-add → SPN-activation chains detected.

### Q3: Ownership → Credential Chain

<If Q3 returns results:>
| Owner Added | Cred Operation | Hours Gap | New Owner | Same Actor? | App |
|-------------|---------------|-----------|-----------|-------------|-----|
| <date> | <date> | <N> | <upn> | <yes/no> | <app> |

<If Q3 returns 0:>
✅ No ownership → credential modification chains detected.

### Q5: Credential Add → Graph API Lateral Movement

<If Q5 returns results:>
| Cred Added | Actor | App | Endpoint Category | Graph Calls | Methods | Success Rate |
|------------|-------|-----|-------------------|-------------|---------|-------------|
| <date> | <upn> | <app> | <category> | <N> | <methods> | <pct>% |

<If Q5 returns 0:>
✅ No credential-add → Graph API lateral movement chains detected.

> **Note:** MicrosoftGraphActivityLogs requires Entra ID P1/P2 + diagnostic settings. If table not found, report as: `❓ MicrosoftGraphActivityLogs not available — cannot assess Graph API lateral movement.`

### Q6: Credential Add → Permission Escalation

<If Q6 returns results:>
| Cred Added | Perm Escalation | Hours Gap | Actor | App | Escalation Operation |
|------------|----------------|-----------|-------|-----|---------------------|
| <date> | <date> | <N> | <upn> | <app> | <operation> |

<If Q6 returns 0:>
✅ No credential-add → permission-escalation chains detected.

### Q7: Multi-App Ownership Spread

<If Q7 returns results:>
| User | Apps Owned | Spread Window (hrs) | App Names | Added By |
|------|-----------|---------------------|-----------|----------|
| <upn> | <N> | <N> | <names> | <actors> |

<If Q7 returns 0:>
✅ No multi-app ownership spread detected (threshold: ≥3 apps).

### Q8: App Governance & OAuth Incident Cross-Reference

> **Purpose:** Cross-reference Phase 1 flagged apps with existing Microsoft detections (App Governance alerts, Defender XDR OAuth alerts, Attack Disruption incidents). This validates skill findings against Microsoft's own detection coverage and surfaces apps with multi-source detections.

<If Q8 returns results:>

**Detection Summary:**
| App Name | App ID | Alert Count | Detection Sources | Detection Breadth | Highest Severity | Has Attack Disruption |
|----------|--------|-------------|-------------------|-------------------|------------------|-----------------------|
| <name> | <id> | <N> | <sources> | <N> | <severity> | ✅/❌ |

**Cross-Reference with Phase 1:**
- 🔴 **Both skill and Microsoft flagged:** <list apps found in BOTH Phase 1 dangerous-permission inventory AND Q8 detections — these are confirmed high-priority>
- 🟠 **Skill-only (no Microsoft detection):** <list apps from Phase 1 that Q8 did NOT detect — skill's unique value-add, may indicate detection gap in App Governance>
- 🔵 **Microsoft-only (not in skill scope):** <list apps from Q8 that are NOT in Phase 1 — may not have dangerous permissions but triggered behavioral alerts>

<If Q8 returns 0:>
✅ No App Governance, OAuth, or Attack Disruption alerts detected for any apps in the last 90 days.

---

## App Permission Risk Score Card

```
┌──────────────────────────────────────────────────────────────┐
│       APP PERMISSION RISK SCORE: <NN>/100                    │
│                Rating: <EMOJI> <RATING>                      │
├──────────────────────────────────────────────────────────────┤
│ Perm Concentration [<bar>] <N>/20  (<detail>)                │
│ Owner Risk         [<bar>] <N>/20  (<detail>)                │
│ Credential Hygiene [<bar>] <N>/20  (<detail>)                │
│ Cross-Tenant Exp.  [<bar>] <N>/20  (<detail>)                │
│ Active Abuse Sigs  [<bar>] <N>/20  (<detail>)                │
└──────────────────────────────────────────────────────────────┘
```

### Dimension Details

| Dimension | Score | Evidence |
|-----------|-------|----------|
| **Permission Concentration** | 🔴/🟠/🟡 <N>/20 | <N> apps with dangerous perms; list golden ticket / critical perms found |
| **Owner Risk** | 🔴/🟠/🟡 <N>/20 | <N> ownerless apps; non-admin owners on critical apps; Identity Protection signals |
| **Credential Hygiene** | 🔴/🟠/🟡 <N>/20 | Multi-secret apps; stale credentials; dormant privileged apps |
| **Cross-Tenant Exposure** | 🔴/🟠/🟡 <N>/20 | Foreign SPNs with critical perms; unknown tenant IDs; resource breadth |
| **Active Abuse Signals** | 🔴/🟠/🟡 <N>/20 | Which chain queries (Q1–Q8) returned critical results; key actors; Q8 detection breadth |

---

## Security Assessment

| Factor | Finding |
|--------|---------|
| <emoji> **<Factor>** | <Evidence-based finding> |

---

## Recommendations

> **Key context:** This skill detects signals that [Microsoft App Governance](https://learn.microsoft.com/en-us/defender-cloud-apps/app-governance-manage-app-governance) does NOT — specifically the cross-table correlation between user compromise signals and app abuse chains. Recommendations should complement App Governance, not duplicate it.

**Minimum recommendation checklist** — include ALL applicable items (skip only if the finding doesn't exist in the data). Order by severity (🔴 first):

| # | Must-Include Topic | When Applicable |
|---|-------------------|------------------|
| a | **Golden ticket / critical cross-tenant SPN remediation** | Any foreign SPN with `AppRoleAssignment.ReadWrite.All` or `Directory.ReadWrite.All` |
| b | **Compromised-user consent investigation** | Q1 returns `adminConfirmedUserCompromised` or `confirmedCompromised` chains |
| c | **Owner assignment for ownerless dangerous apps** | Any ownerless app with dangerous perms |
| d | **Stale credential rotation** | Any secret >365 days old on an app with dangerous perms |
| e | **Multi-credential reduction** | Any app with ≥3 active secrets |
| f | **Non-admin owner risk mitigation** | Non-admin user owns app with 🔴-level perms |
| g | **Single-user blast radius reduction** | Any user owns ≥20 apps (pipeline or otherwise) |
| h | **Dormant privileged app disposition** | App with dangerous perms but no credentials |
| i | **Expired-credential permission cleanup** | App with expired creds that still retains dangerous permission grants |
| j | **App Governance enablement** | Always include if not already deployed (standard closing recommendation) |

1. <emoji> **<Priority action>** — <evidence and rationale>
2. ...

---

## Related Workspace Resources

| Resource | Relationship |
|----------|-------------|
| `queries/identity/app_credential_management.md` | Individual event queries — complements chain detections |
| `queries/identity/service_principal_scope_drift.md` | SPN behavioral baseline — use for post-detection deep dive |
| `.github/skills/scope-drift-detection/spn/SKILL.md` | Full SPN investigation workflow — run on SPNs flagged by Q2 |
| `queries/cloud/behavior_entities.md` Q6 | MCAS `UnusualAdditionOfCredentialsToAnOauthApp` detection |

---

## Appendix: Query Execution Summary

| Phase | Query | Description | Records |
|-------|-------|-------------|--------|
| 1 | P1 | Find Graph SP ID | 1 |
| 1 | P2 | List permission grants | <N> |
| 1 | P3 | Resolve permission names | <N> |
| 1 | P4 | Filter dangerous perms | <N> |
| 1 | P5 | Resolve owners | <N> apps |
| 1 | P6 | Assess owner risk | <N> owners |
| 1 | P7 | Credential hygiene | <N> apps |
| 2 | Q1 | Risky User → App Ops | <N> |
| 2 | Q2 | Cred → SPN Activation | <N> |
| 2 | Q3 | Ownership → Credential | <N> |
| 2 | Q4 | Cross-Tenant SPNs | <N> |
| 2 | Q5 | Cred → Graph API | <N> |
| 2 | Q6 | Cred → Permission Esc. | <N> |
| 2 | Q7 | Ownership Spread | <N> |
| 2 | Q8 | App Gov & OAuth Cross-Ref | <N> |
````

---

## Markdown File Report Template

When outputting to markdown file, use the same structure as the Inline Report Template above, saved to:

```
reports/app-registration-posture/App_Registration_Posture_Report_{tenant}_YYYYMMDD_HHMMSS.md
```

Include the following additional sections in the file report that are omitted from inline:

1. **Full permission grant table** (all apps with Graph permissions, not just dangerous ones)
2. **Complete owner listing** (all owners for all flagged apps, including creator fallback from AuditLogs)
3. **Credential detail table** (full `passwordCredentials` and `keyCredentials` with expiry dates)
4. **Cross-tenant SPN detail** (full resource access breakdown per foreign SPN)
5. **Raw Q1–Q8 results** (full chain detection output, not summarized)
6. **MITRE ATT&CK mapping table** (techniques detected vs not detected)

### File Report Header

```markdown
# App Registration Security Posture Report

**Generated:** YYYY-MM-DD HH:MM UTC  
**Data Sources:** Graph API + Advanced Hunting (AuditLogs, AADServicePrincipalSignInLogs, AADUserRiskEvents, MicrosoftGraphActivityLogs, AlertInfo, AlertEvidence)  
**KQL Lookback:** <N> days (Q1–Q7); 90 days (Q8)  
**Tenant:** <tenant name> (<tenant ID>)  
**Apps with Graph Permissions:** <N>  
**Apps with Dangerous Permissions:** <N>  
**Cross-Tenant SPNs:** <N>  
**Chain Detections (Q1–Q8):** <N total hits>

---
```

### File Report Differences from Inline

The file report uses the same inline template structure with these additions:
- **Q1–Q8 chain sections**: Include ALL result rows (inline collapses 🟡 Low into the summary)
- **Cross-Tenant SPN Exposure table**: Add `Auth Methods` and `Locations` columns (inline may abbreviate)
- **Credential Hygiene table**: Add `Application Object` column (✅ Exists / ❌ No local object)
- **Dimension Details table**: Always included (inline may omit if score is low)
- **Dormant privileged apps callout**: Include in credential hygiene section even for 🟢 apps

---

## Known Pitfalls

### 1. Application ObjectId ≠ ServicePrincipal ObjectId

**Problem:** The same app has different GUIDs in `TargetResources[0].id` depending on the AuditLog operation type. Credential operations reference the Application ObjectId; permission/consent operations reference the ServicePrincipal ObjectId.

**Impact:** Joining credential events to permission events on `TargetResources[0].id` returns zero results even when both operations target the same app.

**Solution:** Q6 joins on `Actor` + `TargetAppName` (display name match) instead of ObjectId. This works reliably for same-actor chains.

### 2. Ownership Operations — Target Name in modifiedProperties

**Problem:** For "Add owner to application", `TargetResources[0]` is the new owner (User type), not the app. The app name is buried in `TargetResources[0].modifiedProperties[1].newValue`.

**Solution:** Extract with `tostring(parse_json(tostring(ModProps[1].newValue)))`. Field name is `Application.DisplayName`.

### 3. OperationName Trailing Spaces

**Problem:** `"Update application – Certificates and secrets management "` has a trailing space. String equality (`==`) fails without it.

**Solution:** Use `in~()` with the exact string (including trailing space) or use `has` for substring matching.

### 4. Cross-Tenant SPNs Have No Local Application Object

**Problem:** Graph API calls to `/v1.0/applications?$filter=displayName eq 'X'` return empty for SPNs owned by foreign tenants — they only have a ServicePrincipal object in your tenant, not an Application object.

**Impact:** Cannot retrieve ownership or credential details for cross-tenant SPNs via local Graph API.

**Solution:** Identify cross-tenant SPNs via Q4 (`AppOwnerTenantId != AADTenantId`). Report them separately with a note that ownership is managed by the foreign tenant.

### 5. Graph API `requiredResourceAccess` ≠ Granted Permissions

**Problem:** The Application object's `requiredResourceAccess` shows what the app **requests** (manifest), not what's been **admin-consented/granted**.

**Solution:** Always use `appRoleAssignedTo` on the resource service principal (Step P2) for the authoritative granted permissions list.

### 6. Red Team Apps May Have Owners Stripped

**Problem:** Attack simulation tools often remove app ownership post-creation to evade detection. Graph API returns no owners.

**Solution:** Fall back to AuditLogs `"Add application"` OperationName to find the original creator — AuditLogs retain the `InitiatedBy` actor forever.

### 7. MicrosoftGraphActivityLogs May Not Be Available

**Problem:** Q5 requires `MicrosoftGraphActivityLogs`, which needs Entra ID P1/P2 and diagnostic settings to be enabled. Not all tenants have this.

**Impact:** If the table doesn't exist, Q5 returns an error.

**Solution:** If Q5 fails with "table not found", report as `❓ MicrosoftGraphActivityLogs not available` and skip — do not fail the entire assessment. The other 7 chain queries and Graph API posture still provide substantial coverage.

### 8. `suspiciousAuthAppApproval` Self-Referencing in Q1

**Problem:** When a consent grant occurs, Identity Protection may flag the same event as a `suspiciousAuthAppApproval` risk detection. Q1 then correlates the risk event WITH the consent operation, creating a circular detection.

**Solution:** If Q1 results are dominated by `suspiciousAuthAppApproval` risk types, note in the report that these may be self-referencing. The user can filter with `| where RiskTypes !has "suspiciousAuthAppApproval"` for higher-confidence chains.

---

## Quality Checklist

Before delivering the report, verify:

- [ ] Phase 1 (Graph API) completed: P1–P7 steps executed
- [ ] Phase 2 (KQL) completed: Q1–Q8 all executed via `RunAdvancedHuntingQuery`
- [ ] Zero-result queries are reported with explicit absence confirmation (✅ pattern)
- [ ] Graph API used `appRoleAssignedTo` (NOT `requiredResourceAccess`) for permission inventory
- [ ] App ownership queried from Application object (NOT ServicePrincipal)
- [ ] Cross-tenant SPNs reported separately with foreign-tenant note
- [ ] The App Permission Risk Score calculation is transparent with per-dimension evidence
- [ ] Permission inventory includes human-readable names (not just GUIDs)
- [ ] Owner risk assessment includes directory role check + Identity Protection status
- [ ] Credential hygiene includes expiry dates, not just counts
- [ ] Chain detection results include triage priority (🔴/🟠/🟡) for each finding
- [ ] Q8 cross-reference includes three-way breakdown (both flagged, skill-only, Microsoft-only)
- [ ] Recommendations complement (not duplicate) App Governance capabilities
- [ ] All hyperlinks copied verbatim from URL Registry — no fabricated URLs
- [ ] No PII from live environments in the SKILL.md file itself
- [ ] Total elapsed time reported

---

## SVG Dashboard Generation

> 📊 **Optional post-report step.** After an App Registration Posture report is generated, the user can request a visual SVG dashboard.

**Trigger phrases:** "generate SVG dashboard", "create a visual dashboard", "visualize this report", "SVG from the report"

### How to Request a Dashboard

- **Same chat:** "Generate an SVG dashboard from the report" — data is already in context.
- **New chat:** Attach or reference the report file, e.g. `#file:reports/app-registration-posture/App_Registration_Posture_Report_<tenant>_<date>.md`
- **Customization:** Create an `svg-widgets.yaml` in this skill folder before requesting — the renderer reads it at generation time.

### Execution

```
Step 1:  Read svg-widgets.yaml (this skill's widget manifest, if it exists)
Step 2:  Read .github/skills/svg-dashboard/SKILL.md (rendering rules — Manifest Mode if yaml exists, Freeform Mode otherwise)
Step 3:  Read the completed report file (data source)
Step 4:  Render SVG → save to reports/app-registration-posture/{report_name}_dashboard.svg
```
