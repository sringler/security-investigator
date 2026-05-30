# npm Dependency Confusion Campaign Hunting — 33 Malicious Packages (May 2026)

**Created:** 2026-05-30  
**Platform:** Both  
**Tables:** DeviceProcessEvents, DeviceFileEvents, DeviceNetworkEvents, DeviceEvents, DeviceCustomFileEvents, DeviceCustomScriptEvents, ASimDnsActivityLogs, DeviceTvmSoftwareInventory, CloudProcessEvents, AlertInfo  
**Keywords:** npm, dependency confusion, supply chain, postinstall, package.json, node.exe, node_modules, npm install, recon, RECON_ONLY, oob.moika.tech, X-Secret, scoped package, internal package, typosquat, namespace, obfuscation, postinstall.js, init.js, tmpdir, detached process, windowsHide, credential harvesting, yarn, pnpm, npx, package-lock.json, yarn.lock, SberPay, capibar  
**MITRE:** T1195.002, T1059.007, T1027, T1071.001, T1082, T1552.001, T1497, T1546, T1041, T1070.004  
**Domains:** endpoint  
**Timeframe:** Last 30 days (configurable)

---

## Overview

This hunting campaign targets TTPs and IoCs from a **dependency confusion campaign** disclosed May 29, 2026, in which **33+ malicious npm packages** were published across **9 organization scopes** by a single operator using three maintainer aliases. Unlike a maintainer-account hijack of a popular package (see the related [March 2026 axios compromise](../2026-03/npm_supply_chain_attack.md)), this campaign relies on **dependency confusion / namespace squatting** — publishing public packages that impersonate the names of organizations' *private internal* packages, with artificially inflated version numbers so that a misconfigured resolver prefers the public malicious version over the legitimate private one.

The campaign was designed as a **two-phase operation**: the published packages run in a **recon-only mode** (gated by a server-side `RECON_ONLY` toggle and per-package `*_RECON_ONLY` environment variables), profiling developer and CI/CD environments now while retaining the ability to switch on full exploitation later. Every C2 request from all three accounts carries the same hard-coded shared-secret HTTP header — a single-operator fingerprint.

> ⚠️ **Lab/testing note:** This file's queries were validated for **syntax and table availability** against a lab tenant. The campaign IoCs (e.g., `oob.moika.tech`, the `X-Secret` value, the 9 scopes) are real-world indicators and are **not** expected to be present in any given environment. Baseline/inventory queries (npm process activity, `node_modules` file activity) will return live results; IoC-matching queries should return **zero** in a clean environment. **No query results are embedded in this file.**

**Key intelligence sources:**
- **[Microsoft Security Blog — 33 malicious npm packages abuse dependency confusion to profile developer environments](https://www.microsoft.com/en-us/security/blog/2026/05/29/33-malicious-npm-packages-abuse-dependency-confusion-profile-developer-environments/)** (campaign analysis, IoCs, MDE detections, sample AH queries)

### Threat Summary

| Aspect | Detail |
|--------|--------|
| **Campaign type** | Dependency confusion / namespace squatting against private internal package names |
| **Operator** | Single operator using three npm maintainer aliases (shared infrastructure + shared secret) |
| **Maintainer aliases** | `mr.4nd3r50n` (26 packages, May 28), `ce-rwb` (7 packages, May 28), `t-in-one` (12 packages, May 29) |
| **Maintainer emails** | `mr.4nd3r50n@yandex[.]ru`, `ogvanta@yandex[.]ru` (ce-rwb), `t-in-one@yandex[.]ru` |
| **Package count** | 33+ malicious packages across 9 organization scopes |
| **Operational design** | Two-phase — recon-only now (server-side `RECON_ONLY` toggle + `*_RECON_ONLY` env vars), exploitation deferred |
| **C2 domain** | `oob.moika[.]tech` — payload endpoints `/payload/win`, `/payload/mac`, `/payload/linux` |
| **Lure / spoof domains** | `npm.t-in-one[.]io`, `docs.t-in-one[.]io`, `jira.t-in-one[.]io` (pattern: `github.<scope>.io`, `docs.<scope>.io`, `jira.<scope>.io` in spoofed `package.json` metadata) |
| **Shared secret (high fidelity)** | HTTP header `X-Secret: l95HdDaz3kQx1Zsg3WxH6HvKANf51RY1` sent on every C2 request from all 3 accounts |
| **Delivery mechanism** | `scripts/postinstall.js` declared as `postinstall` hook — auto-executes on `npm install` |
| **Stager** | ~7KB obfuscated `postinstall.js` (~13KB three-layer variant for the May 29 wave); obfuscator.io-style string-array encoding, control-flow flattening, dead-code injection, self-defending |
| **Dropped payload** | `._<scope>_init.js` written to `os.tmpdir()` (e.g. `._cloudplatform-single-spa_init.js`, `._wb-track_init.js`, `._t-in-one_init.js`); run-once/cache dirs at `~/.cache/._<scope>_init/` |
| **Kill switch** | `T_IN_ONE_NO_TELEMETRY` (functional on the May 29 wave); `CLOUDPLATFORM_SINGLE_SPA_NO_TELEMETRY` (README fiction, non-functional) |
| **Pre-staging** | A package version `99.0.7` was pre-staged on 2026-05-04, weeks before the main waves |

### Organization Scopes Targeted (9)

| Scope | Notable packages | Theme |
|-------|-----------------|-------|
| `@cloudplatform-single-spa` | `svp-baas`, `enterprise`, `vpn`, `monitoring`, `ssh-keys`, `security-groups`, `cp-api-gw`, `logaas`, `cnapp-ui` | Cloud platform / infra (mr.4nd3r50n) |
| `@wb-track` | (tracking/analytics-themed) | Logistics / tracking |
| `@data-science` | (ML/data-themed) | Data science |
| `@ce-rwb` | `shared-front`, `llm`, `npm-proto`, `ce-tools-editor-*` | Internal tooling (ce-rwb) |
| `@payments-widget` | `payments-widget-sdk` | Payments |
| `@travel-autotests` | (test automation) | Travel / QA |
| `@t-in-one` | `add_application_service_token`, `get_application_hid`, `form_product_token` | Credential-themed (t-in-one) |
| `@capibar.chat` | `@capibar.chat/ui-kit` | Chat platform (version `99.5.7`/`99.5.8`) |
| `@sber-ecom-core` | `@sber-ecom-core/sberpay-widget` | Impersonates Sberbank SberPay |

### Inflated / Dependency-Confusion Versions

| Version | Used by |
|---------|---------|
| `100.100.100` | `mr.4nd3r50n` packages |
| `99.99.99`, `99.99.100`, `3.5.22` | `ce-rwb` packages |
| `5.7.1` | `@t-in-one` packages |
| `99.5.7`, `99.5.8` | `@capibar.chat`, `@sber-ecom-core` packages |
| `99.0.7` | Pre-staged package on 2026-05-04 |

> Dependency-confusion versioning relies on **artificially high** version numbers (e.g. `99.x`, `100.x`) so a misconfigured resolver chooses the public malicious package over the legitimate private one. Exact version strings drift across packages — treat the **scope names** and **`9x`/`100.x` version prefixes** as the durable indicators rather than any single version string.

### Behavioral Tradecraft (postinstall stager)

| Stage | Behavior | MITRE |
|-------|----------|-------|
| Trigger | `npm install` runs the `postinstall` lifecycle hook → `node scripts/postinstall.js` | T1546, T1059.007, T1195.002 |
| Environment validation | Node `>=16` check; reads project root markers (`package.json`, `yarn.lock`, `.git`) via project-root walk | T1082 |
| Mode gating | Server-side `RECON_ONLY` toggle + `*_RECON_ONLY` env var; per-package `*_PKG`, `*_VER`, `*_SECRET` env vars | T1497 |
| Recon collection | Hostname, username, OS, project metadata, environment variable enumeration | T1082, T1552.001 |
| C2 | HTTPS GET to `oob.moika[.]tech` (30s timeout) with `X-Secret` header; payload fetched from `/payload/<os>` | T1071.001, T1041 |
| Payload drop | Response written to `os.tmpdir()` as `._<scope>_init.js` | T1027, T1070.004 |
| Detached execution | Background child process via `.unref()` + `windowsHide=true` — survives parent `npm install` exit | T1027, T1497 |
| Evasion | obfuscator.io-style obfuscation; CI-aware (checks `CI` env var); cache dedup / run-once dirs | T1027, T1497 |

### MITRE ATT&CK Coverage

| Technique | ID | Relevance |
|-----------|----|-----------|
| Supply Chain Compromise: Compromise Software Supply Chain | T1195.002 | Dependency-confusion packages published to public npm |
| Event Triggered Execution: Installer Packages | T1546 | `postinstall` lifecycle hook auto-executes on `npm install` |
| Command and Scripting Interpreter: JavaScript | T1059.007 | `node scripts/postinstall.js` stager execution |
| Obfuscated Files or Information | T1027 | obfuscator.io-style stager; `._<scope>_init.js` dropped to tmpdir; `windowsHide` |
| System Information Discovery | T1082 | Hostname, username, OS, project-root walk recon |
| Unsecured Credentials: Credentials In Files | T1552.001 | Environment variable enumeration, credential-themed packages (`*_token`, `*_hid`) |
| Virtualization/Sandbox Evasion: System Checks | T1497 | CI detection (`CI` env var), Node version validation, run-once cache dedup |
| Application Layer Protocol: Web Protocols | T1071.001 | HTTPS GET C2 to `oob.moika[.]tech` with `X-Secret` header |
| Exfiltration Over C2 Channel | T1041 | Recon data sent to C2 (recon-only phase) |
| Indicator Removal: File Deletion | T1070.004 | Run-once/cache dirs, tmpdir payload management |

### Microsoft Defender Detection Names

> Source: [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/05/29/33-malicious-npm-packages-abuse-dependency-confusion-profile-developer-environments/) — Use these for `AlertInfo`/`SecurityAlert` correlation and confirming MDE coverage.

| Type | Detection Name |
|------|---------------|
| Antivirus (signature) | `Trojan:JS/ObfusNpmJs.SA` |
| Antivirus (signature) | `Trojan:JS/ObfusNpmJs` |
| Behavioral (MDE) | Suspicious Node.js process behavior |
| Behavioral (MDE) | Suspicious detached child process spawned with windowsHide=true |
| Behavioral (MDE) | Detached Node.js process surviving parent npm install exit |
| Behavioral (MDE) | Suspicious file creation in temporary directory by Node.js binary |
| Behavioral (MDE) | Suspicious persistence file creation in user cache directory |
| Behavioral (MDE) | Suspicious obfuscated JavaScript execution |
| Behavioral (MDE) | Anomalous environment variable usage in npm lifecycle script |
| Network | Connection to a custom network indicator |

### IoCs

| Indicator | Type | Notes |
|-----------|------|-------|
| `oob.moika[.]tech` | Domain | C2 server (recon + payload delivery) |
| `oob.moika[.]tech/payload/win` | URL | Windows payload endpoint |
| `oob.moika[.]tech/payload/mac` | URL | macOS payload endpoint |
| `oob.moika[.]tech/payload/linux` | URL | Linux payload endpoint |
| `npm.t-in-one[.]io` | Domain | Lure/spoof domain in package metadata |
| `docs.t-in-one[.]io` | Domain | Lure/spoof domain in package metadata |
| `jira.t-in-one[.]io` | Domain | Lure/spoof domain in package metadata |
| `l95HdDaz3kQx1Zsg3WxH6HvKANf51RY1` | HTTP header value | `X-Secret` shared secret on every C2 request (single-operator marker) |
| `mr.4nd3r50n` | npm maintainer alias | 26 packages, May 28 |
| `ce-rwb` | npm maintainer alias | 7 packages, May 28 |
| `t-in-one` | npm maintainer alias | 12 packages, May 29 |
| `mr.4nd3r50n@yandex[.]ru` | Email | mr.4nd3r50n npm account |
| `ogvanta@yandex[.]ru` | Email | ce-rwb npm account |
| `t-in-one@yandex[.]ru` | Email | t-in-one npm account |
| `@cloudplatform-single-spa` | npm scope | Targeted org scope |
| `@wb-track` | npm scope | Targeted org scope |
| `@data-science` | npm scope | Targeted org scope |
| `@ce-rwb` | npm scope | Targeted org scope |
| `@payments-widget` | npm scope | Targeted org scope |
| `@travel-autotests` | npm scope | Targeted org scope |
| `@t-in-one` | npm scope | Targeted org scope |
| `@capibar.chat` | npm scope | Targeted org scope |
| `@sber-ecom-core` | npm scope | Targeted org scope (impersonates Sberbank) |
| `scripts/postinstall.js` | File path | Obfuscated stager (~7KB; ~13KB three-layer May 29 variant) |
| `._<scope>_init.js` | File pattern | Dropped payload in `os.tmpdir()` (regex `^\._.*_init\.js$`) |
| `~/.cache/._<scope>_init/` | Dir pattern | Run-once / cache dedup directory |
| `*_RECON_ONLY` | Env var | Recon-mode toggle (per-package prefix) |
| `*_SECRET`, `*_PKG`, `*_VER` | Env var | Per-package operational env vars |
| `T_IN_ONE_NO_TELEMETRY` | Env var | Functional kill switch (May 29 wave) |
| `100.100.100`, `99.99.99`, `99.99.100`, `99.5.7`, `99.5.8`, `99.0.7`, `5.7.1`, `3.5.22` | Package versions | Inflated dependency-confusion versions |

### References

| Source | URL |
|--------|-----|
| **Microsoft Security Blog — 33 malicious npm packages abuse dependency confusion** | https://www.microsoft.com/en-us/security/blog/2026/05/29/33-malicious-npm-packages-abuse-dependency-confusion-profile-developer-environments/ |
| Related: axios npm supply chain compromise (March 2026) | [../2026-03/npm_supply_chain_attack.md](../2026-03/npm_supply_chain_attack.md) |
| npm maintainer profile — mr.4nd3r50n | https://www.npmjs.com/~mr.4nd3r50n |
| npm maintainer profile — ce-rwb | https://www.npmjs.com/~ce-rwb |
| npm maintainer profile — t-in-one | https://www.npmjs.com/~t-in-one |
| Microsoft Learn — Defender for Endpoint custom network indicators | https://learn.microsoft.com/en-us/defender-endpoint/indicator-ip-domain |

---

## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [— npm / yarn / pnpm Install Activity Baseline (DeviceProcessEvents)](#query-1--npm--yarn--pnpm-install-activity-baseline-deviceprocessevents) | Dashboard | `DeviceProcessEvents` |
| 2 | [— Targeted Scope Package Install Detection (DeviceProcessEvents)](#query-2--targeted-scope-package-install-detection-deviceprocessevents) | Detection | `DeviceProcessEvents` |
| 3 | [— Credential-Themed Package Name Install (DeviceProcessEvents)](#query-3--credential-themed-package-name-install-deviceprocessevents) | Investigation | `DeviceProcessEvents` |
| 4 | [— Inflated Dependency-Confusion Version Install (DeviceProcessEvents)](#query-4--inflated-dependency-confusion-version-install-deviceprocessevents) | Investigation | `DeviceProcessEvents` |
| 5 | [— C2 / Lure Domain Network Connections (DeviceNetworkEvents)](#query-5--c2--lure-domain-network-connections-devicenetworkevents) | Investigation | `DeviceNetworkEvents` |
| 6 | [— Shared-Secret Header in Network Telemetry (DeviceNetworkEvents)](#query-6--shared-secret-header-in-network-telemetry-devicenetworkevents) | Investigation | `DeviceNetworkEvents` |
| 7 | [— Dropped Payload `._<scope>_init.js` Artifacts (DeviceFileEvents)](#query-7--dropped-payload-scopeinitjs-artifacts-devicefileevents) | Investigation | `DeviceFileEvents` |
| 8 | [— Node.js Writing `.js` Payloads to Temp Directory (DeviceFileEvents)](#query-8--nodejs-writing-js-payloads-to-temp-directory-devicefileevents) | Investigation | `DeviceFileEvents` |
| 9 | [— Campaign Env-Var Markers in Process Commands (DeviceProcessEvents)](#query-9--campaign-env-var-markers-in-process-commands-deviceprocessevents) | Investigation | `DeviceProcessEvents` |
| 10 | [— npm postinstall Hook Execution (DeviceProcessEvents)](#query-10--npm-postinstall-hook-execution-deviceprocessevents) | Investigation | `DeviceProcessEvents` |
| 11 | [— Detached Hidden Node.js Child Process (DeviceProcessEvents)](#query-11--detached-hidden-nodejs-child-process-deviceprocessevents) | Investigation | `DeviceProcessEvents` |
| 12 | [— C2 DNS Resolution via ASIM (ASimDnsActivityLogs)](#query-12--c2-dns-resolution-via-asim-asimdnsactivitylogs) | Investigation | `ASimDnsActivityLogs` |
| 13 | [— C2 DNS via MDE DNS Events (DeviceEvents)](#query-13--c2-dns-via-mde-dns-events-deviceevents) | Investigation | `DeviceEvents` |
| 14 | [— node.exe Anomalous Outbound Connections (DeviceNetworkEvents)](#query-14--nodeexe-anomalous-outbound-connections-devicenetworkevents) | Detection | `DeviceNetworkEvents` |
| 15 | [— CDC Dropped Payload Detection (DeviceCustomFileEvents)](#query-15--cdc-dropped-payload-detection-devicecustomfileevents) | Detection | `DeviceCustomFileEvents` |
| 16 | [— CDC node_modules File Activity Audit (DeviceCustomFileEvents)](#query-16--cdc-nodemodules-file-activity-audit-devicecustomfileevents) | Investigation | `DeviceCustomFileEvents` |
| 17 | [— CDC AMSI: Campaign Indicators in Script Content (DeviceCustomScri...](#query-17--cdc-amsi-campaign-indicators-in-script-content-devicecustomscriptevents) | Investigation | `DeviceCustomScriptEvents` |
| 18 | [— CDC AMSI: Obfuscated postinstall Patterns (DeviceCustomScriptEvents)](#query-18--cdc-amsi-obfuscated-postinstall-patterns-devicecustomscriptevents) | Investigation | `DeviceCustomScriptEvents` |
| 19 | [— package.json / Lockfile / .npmrc Modifications (DeviceFileEvents)](#query-19--packagejson--lockfile--npmrc-modifications-devicefileevents) | Investigation | `DeviceFileEvents` |
| 20 | [— Campaign Packages in TVM Software Inventory (DeviceTvmSoftwareInv...](#query-20--campaign-packages-in-tvm-software-inventory-devicetvmsoftwareinventory) | Posture | `DeviceTvmSoftwareInventory` |
| 21 | [— Cloud Workload Stager / C2 Activity (CloudProcessEvents)](#query-21--cloud-workload-stager--c2-activity-cloudprocessevents) | Investigation | `CloudProcessEvents` |
| 22 | [— ASIM Web Session C2 Detection (_Im_WebSession)](#query-22--asim-web-session-c2-detection-imwebsession) | Detection | — |
| 23 | [— ASIM Network Session C2 Detection (_Im_NetworkSession)](#query-23--asim-network-session-c2-detection-imnetworksession) | Detection | — |
| 24 | [— Defender Detection Correlation (AlertInfo)](#query-24--defender-detection-correlation-alertinfo) | Detection | `AlertInfo` |
| 25 | [— npm Ecosystem Exposure Inventory (DeviceProcessEvents)](#query-25--npm-ecosystem-exposure-inventory-deviceprocessevents) | Posture | `DeviceProcessEvents` |


## Tuning Guidance

This campaign's durable, low-noise indicators are: the **C2 domain** (`oob.moika.tech`), the **`X-Secret` shared-secret value**, the **9 org scopes**, the **`._<scope>_init.js` dropped-payload pattern**, and **`*_RECON_ONLY` env vars**. Network/header/scope IoC matches are near-zero-FP — treat any hit as high-confidence. The behavioral and inventory queries are noisier and require environment-specific allowlisting. General tuning principles:

- **Legitimate scoped packages:** If your organization legitimately publishes private packages under any of the 9 scope names (most likely `@data-science`, `@payments-widget`, `@travel-autotests`), the scope-name queries will match benign installs. Pivot on the **`9x`/`100.x` inflated version**, the **public registry source**, or correlate with a C2/`X-Secret`/`._init.js` hit before escalating. Add an allowlist of your known-good internal versions.
- **Legitimate postinstall hooks:** Many popular packages (`esbuild`, `node-sass`, `cypress`, `electron`, `puppeteer`, `sharp`, native-addon builders) use `postinstall`/`preinstall` hooks legitimately. The postinstall-execution query (Query 11) will be noisy — combine with the **detached/`windowsHide`** signal (Query 12) or a **tmpdir `.js` drop** (Query 9) to raise fidelity.
- **`node_modules` file noise:** `node_modules` directories generate very high file-event volume during installs. The CDC audit queries (Queries 16–17) exclude bundled app `node_modules` (`WindowsApps`, `.vscode\extensions`, `.vscode-insiders\extensions`, `Microsoft.GamingApp`) — extend these exclusions for any IDE/runtime that ships bundled modules in your fleet (e.g. JetBrains, Cursor, Electron apps).
- **Developer/CI hosts dominate:** Build agents, developer workstations, and CI runners will produce nearly all npm activity. Consider scoping detections to **non-developer** assets (where npm activity is itself anomalous) or maintaining a developer-host allowlist for the inventory queries.
- **`node.exe` anomalous-network query (Query 15):** High FP rate — `node.exe` legitimately reaches many SaaS/AI/registry endpoints (`registry.npmjs.org`, `api.anthropic.com`, `api.openai.com`, `api.telegram.org`, CDNs). The query excludes common destinations; build on it with your environment's known-good Node egress allowlist before alerting.
- **AMSI blind spot (Queries 17–18):** `DeviceCustomScriptEvents` (AMSI) captures PowerShell/VBScript/JScript — it does **not** see Node.js execution directly. AMSI value here is for any **PowerShell wrapper** invoked by the stager or downstream payload; the obfuscated `postinstall.js` itself is JS and won't appear. Don't rely on AMSI alone for this campaign.
- **AMSI `npm` substring FP (validated):** A bare `ScriptContent has "npm"` filter false-positives on PowerShell's `$_.NPM` property (NonPaged Memory, emitted by `Get-Process` formatters) — observed in Azure **Guest Configuration** `enable.ps1` (`Microsoft.GuestConfiguration.ConfigurationforWindows`) across multiple hosts with an identical `ScriptContentSHA256`. The catalog's AMSI queries deliberately filter on **specific campaign strings** (Query 17) or **node-context + behavioral markers** (Query 18) rather than bare `npm`; if you broaden them, exclude `$_.NPM` / Guest Configuration to avoid this benign match.
- **CDC node_modules noise (validated):** Folder-only `node_modules` matching in `DeviceCustomFileEvents` is dominated by installers (`svchost.exe`, `setup.exe`, `code-insiders` setup) extracting *bundled* modules — not real installs. Query 16 now groups by `InitiatingProcessFileName` and excludes installer/setup processes; filter to `IsPackageManagerDriven == true` for genuine npm/node activity.
- **CDC table availability:** `DeviceCustom*` tables require MDE Custom Data Collection rules. If a CDC query returns *"Failed to resolve table"*, the table isn't provisioned in that workspace — treat as a telemetry gap, not absence of activity, and fall back to the standard `DeviceFileEvents`/`DeviceProcessEvents` equivalents.
- **`package.json`/lockfile telemetry sparsity (Query 20):** Global installs (`npm i -g`) and many install flows do not generate per-file `package.json`/lockfile events in `DeviceFileEvents`. Expect this query to be sparse; use it as corroboration, not a primary detection.
- **Lookback & tool choice:** Queries use a 30-day `Timestamp` window for Advanced Hunting. For historical exposure scoping beyond 30 days, run the equivalent in **Sentinel Data Lake** (`mcp_sentinel-data_query_lake`) and change `Timestamp` → `TimeGenerated`.
- **Version-string drift:** The inflated version list (`99.x`, `100.100.100`, etc.) is campaign-observed but not exhaustive. Prefer the regex/`startswith` version-prefix approach in Query 4 over hardcoded exact versions when hunting forward.

---

## Query Catalog

### Query 1 — npm / yarn / pnpm Install Activity Baseline (DeviceProcessEvents)

**Goal:** Audit all npm/yarn/pnpm package install activity across the MDE fleet. Foundation query for dependency-confusion exposure assessment — establishes which hosts and users run package installs.  
**MITRE:** T1195.002, T1059.007

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Audit/inventory query using summarize with make_set and dcount — not suitable for CD alerting."
-->

```kql
// Audit all npm/yarn/pnpm install activity across fleet
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has_any ("npm install", "npm i ", "npm ci", "yarn add", "yarn install", "pnpm install", "pnpm add", "bun install", "bun add")
| extend PackageManagerRaw = case(
    ProcessCommandLine has "pnpm", "pnpm",
    ProcessCommandLine has "yarn", "yarn",
    ProcessCommandLine has "bun", "bun",
    ProcessCommandLine has "npm", "npm",
    "unknown")
| summarize
    InstallCount = count(),
    Devices = make_set(DeviceName, 20),
    Users = make_set(AccountName, 20),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    SampleCommands = make_set(ProcessCommandLine, 20)
    by PackageManagerRaw
| order by InstallCount desc
```

---

### Query 2 — Targeted Scope Package Install Detection (DeviceProcessEvents)

**Goal:** Detect any `npm`/`yarn`/`pnpm` install referencing one of the 9 campaign org scopes. A public install of a scoped package that should only exist in your private registry is the core dependency-confusion indicator.  
**MITRE:** T1195.002

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "InitialAccess"
title: "Dependency-confusion scope package install on {{DeviceName}} by {{AccountName}}"
impactedAssets:
  - type: device
    identifier: deviceName
  - type: user
    identifier: accountName
recommendedActions: "A package matching a known dependency-confusion campaign scope was installed. Verify whether this scope is a legitimate private scope in your org and whether the resolved version is an inflated public version (99.x / 100.x). If public+inflated, treat as compromise: isolate, capture os.tmpdir() for ._<scope>_init.js, enumerate environment variables that may have been exfiltrated, and rotate exposed secrets."
adaptation_notes: "Already row-level. Add DeviceId + ReportId. Allowlist legitimately-published internal scope versions if any of these scopes are real in your org."
-->

```kql
// Detect installs referencing campaign org scopes
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("node.exe", "node", "npm.cmd", "npm.exe", "npx.cmd", "npx.exe", "yarn.cmd", "pnpm.cmd")
    or ProcessCommandLine has_any ("npm install", "npm i ", "yarn add", "pnpm add", "npx ")
| where ProcessCommandLine has_any (
    "@cloudplatform-single-spa", "@wb-track", "@data-science", "@ce-rwb",
    "@payments-widget", "@travel-autotests", "@t-in-one", "@capibar.chat", "@sber-ecom-core")
| project
    Timestamp,
    DeviceName,
    AccountName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    FolderPath
| order by Timestamp desc
```

---

### Query 3 — Credential-Themed Package Name Install (DeviceProcessEvents)

**Goal:** Detect installs of the campaign's credential-themed package names (e.g. `add_application_service_token`, `get_application_hid`, `form_product_token`) from the `@t-in-one` scope, plus other distinctive package names. These names are crafted to mirror internal credential/token helper packages.  
**MITRE:** T1195.002, T1552.001

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Credential Access"
title: "Credential-themed dependency-confusion package install on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
  - type: user
    identifier: accountName
recommendedActions: "A credential-themed package name from this campaign was installed. These packages profile environment variables (which frequently hold tokens/secrets in dev and CI). Enumerate environment variables on the host, rotate any secrets that could have been read, and check for ._<scope>_init.js in os.tmpdir()."
adaptation_notes: "Already row-level. Add DeviceId + ReportId. Package-name list is campaign-specific; expand as new package names are published."
-->

```kql
// Detect campaign credential-themed / distinctive package names
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has_any (
    "add_application_service_token", "get_application_hid", "form_product_token",
    "sberpay-widget", "svp-baas", "cp-api-gw", "cnapp-ui", "ce-tools-editor",
    "payments-widget-sdk", "npm-proto")
| project
    Timestamp,
    DeviceName,
    AccountName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    FolderPath
| order by Timestamp desc
```

---

### Query 4 — Inflated Dependency-Confusion Version Install (DeviceProcessEvents)

**Goal:** Detect installs that pin or resolve an artificially inflated version (`99.x`, `100.x`, or the specific observed versions) — the mechanism that makes a public package win over a private one. Catches the campaign even for package names not yet enumerated.  
**MITRE:** T1195.002

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Heuristic version-prefix match — moderate FP potential (legitimate packages occasionally use high versions). Best used as a hunt or correlated with scope/C2 hits, not standalone CD."
-->

```kql
// Detect installs referencing inflated dependency-confusion versions
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("node.exe", "node", "npm.cmd", "npm.exe", "npx.cmd", "npx.exe", "yarn.cmd", "pnpm.cmd")
    or ProcessCommandLine has_any ("npm install", "npm i ", "yarn add", "pnpm add")
| where ProcessCommandLine matches regex @"@(99|100)\.\d{1,3}\.\d{1,3}"
    or ProcessCommandLine has_any ("@100.100.100", "@99.99.99", "@99.99.100", "@99.5.7", "@99.5.8", "@99.0.7", "@5.7.1", "@3.5.22")
| project
    Timestamp,
    DeviceName,
    AccountName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    FolderPath
| order by Timestamp desc
```

---

### Query 5 — C2 / Lure Domain Network Connections (DeviceNetworkEvents)

**Goal:** Detect outbound connections to the campaign C2 (`oob.moika.tech`) and lure/spoof domains. The C2 is contacted by the obfuscated stager during the recon phase; a match here is a high-confidence compromise indicator.  
**MITRE:** T1071.001, T1041

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CommandAndControl"
title: "Connection to npm dependency-confusion C2/lure domain from {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "CRITICAL: Host connected to the dependency-confusion campaign C2 or a lure domain. This indicates the obfuscated npm postinstall stager executed. Isolate the device, identify the initiating npm install, capture os.tmpdir() for ._<scope>_init.js, enumerate exposed environment variables/secrets, and rotate all credentials reachable from this host or CI context."
adaptation_notes: "Already row-level. Add DeviceId + ReportId. Near-zero FP — escalate any match."
-->

```kql
// Detect C2 and lure-domain connections
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ("oob.moika.tech", "npm.t-in-one.io", "docs.t-in-one.io", "jira.t-in-one.io")
    or RemoteUrl has "moika.tech"
| project
    Timestamp,
    DeviceName,
    RemoteUrl,
    RemoteIP,
    RemotePort,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessFolderPath
| order by Timestamp desc
```

---

### Query 6 — Shared-Secret Header in Network Telemetry (DeviceNetworkEvents)

**Goal:** Detect the campaign's distinctive `X-Secret: l95HdDaz3kQx1Zsg3WxH6HvKANf51RY1` header value (or C2 host) in `AdditionalFields`. The shared secret is sent on every C2 request from all three operator accounts — a single-operator fingerprint and an extremely high-fidelity indicator.  
**MITRE:** T1071.001

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CommandAndControl"
title: "npm campaign X-Secret header / C2 marker from {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "CRITICAL: The campaign's hard-coded X-Secret value or C2 host appeared in network telemetry. This is a single-operator fingerprint across all three malicious npm accounts. Treat as confirmed C2: isolate, identify the npm install that triggered it, and rotate all secrets reachable from the host/CI context."
adaptation_notes: "Already row-level. Add DeviceId + ReportId. AdditionalFields availability/format depends on connector schema. Near-zero FP."
-->

```kql
// Detect the shared-secret value or C2 host in network AdditionalFields
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where AdditionalFields has "l95HdDaz3kQx1Zsg3WxH6HvKANf51RY1"
    or AdditionalFields has "oob.moika.tech"
| project
    Timestamp,
    DeviceName,
    RemoteUrl,
    RemoteIP,
    RemotePort,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    AdditionalFields
| order by Timestamp desc
```

---

### Query 7 — Dropped Payload `._<scope>_init.js` Artifacts (DeviceFileEvents)

**Goal:** Detect the dropped payload files written to the temp directory using the `._<scope>_init.js` naming pattern, and the run-once cache directories. These artifacts are written by the stager after the C2 fetch and are a direct post-execution indicator.  
**MITRE:** T1027, T1070.004

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Execution"
title: "npm dependency-confusion dropped payload {{FileName}} on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "CRITICAL: A dropped payload matching the campaign's ._<scope>_init.js pattern was created. This means the obfuscated stager ran and fetched a payload from C2. Isolate the device, preserve the file for analysis, identify the initiating npm install, and rotate exposed secrets."
adaptation_notes: "Already row-level with SHA256. Add DeviceId + ReportId. The regex is specific to the campaign naming convention — near-zero FP."
-->

```kql
// Detect dropped payload files and run-once cache dirs
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName matches regex @"^\._.*_init\.js$"
    or FolderPath matches regex @"[\\/]\.cache[\\/]\._.*_init([\\/]|$)"
| project
    Timestamp,
    DeviceName,
    ActionType,
    FileName,
    FolderPath,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    SHA256
| order by Timestamp desc
```

---

### Query 8 — Node.js Writing `.js` Payloads to Temp Directory (DeviceFileEvents)

**Goal:** Detect `node.exe`/`npm`/`npx` writing `.js` files into OS temp/cache directories *outside* `node_modules`. This is the stager's payload-drop behavior generalized — catches the campaign even if the `._<scope>_init.js` naming changes.  
**MITRE:** T1027, T1059.007

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Execution"
title: "Node.js wrote a .js payload to temp directory on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "A Node.js/npm process wrote a JavaScript file into a temp/cache directory outside node_modules — matching the dependency-confusion stager's payload-drop behavior. Review the file content and the initiating npm install. If obfuscated or fetched from oob.moika.tech, treat as compromise."
adaptation_notes: "Already row-level. Add DeviceId + ReportId. May FP on legitimate tooling that caches scripts in temp; correlate with C2/scope hits. Tune the temp-path list to your OS mix."
-->

```kql
// Node.js writing .js files to temp/cache directories outside node_modules
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated", "FileModified")
| where InitiatingProcessFileName in~ ("node.exe", "node", "npm.cmd", "npm.exe", "npx.cmd", "npx.exe")
| where FileName endswith ".js"
| where FolderPath has_any (@"\Temp\", @"\AppData\Local\Temp", "/tmp/", "/var/folders/", ".cache")
| where FolderPath !has "node_modules"
| project
    Timestamp,
    DeviceName,
    ActionType,
    FileName,
    FolderPath,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    SHA256
| order by Timestamp desc
```

---

### Query 9 — Campaign Env-Var Markers in Process Commands (DeviceProcessEvents)

**Goal:** Detect the campaign's operational environment variables (`*_RECON_ONLY`, `*_SECRET`, `*_PKG`, `*_VER`, `T_IN_ONE_NO_TELEMETRY`) appearing in process or initiating-process command lines around npm activity. These gate the stager's recon/exploit mode.  
**MITRE:** T1497, T1059.007

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "DefenseEvasion"
title: "npm campaign recon/telemetry env-var marker on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "A process command line referenced the campaign's recon-mode or kill-switch environment variables in an npm context. Review the full command line and parent npm install. Correlate with C2 connections and dropped-payload artifacts."
adaptation_notes: "Already row-level. Add DeviceId + ReportId. Generic suffixes (_SECRET) may FP on unrelated tooling — the RECON_ONLY / NO_TELEMETRY markers are higher fidelity. Tune as needed."
-->

```kql
// Detect campaign env-var markers in npm-context command lines
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has_any ("_RECON_ONLY", "T_IN_ONE_NO_TELEMETRY", "_NO_TELEMETRY")
    or InitiatingProcessCommandLine has_any ("_RECON_ONLY", "T_IN_ONE_NO_TELEMETRY", "_NO_TELEMETRY")
| where ProcessCommandLine has_any ("node", "npm", "npx")
    or InitiatingProcessFileName in~ ("node.exe", "node", "npm.cmd", "npm.exe", "npx.cmd", "npx.exe")
| project
    Timestamp,
    DeviceName,
    AccountName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc
```

---

### Query 10 — npm postinstall Hook Execution (DeviceProcessEvents)

**Goal:** Detect npm/node running `postinstall`/`preinstall` lifecycle hooks that spawn a `node`/script interpreter — the auto-execution mechanism for `scripts/postinstall.js`. Broad by design; pair with higher-fidelity signals.  
**MITRE:** T1546, T1059.007, T1195.002

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Broad behavioral query — legitimate packages routinely use postinstall hooks (esbuild, cypress, electron, native addons). High FP standalone; correlate with detached/windowsHide (Query 11), tmpdir drop (Query 8), or scope/C2 hits before alerting."
-->

```kql
// npm/node executing postinstall lifecycle hooks
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("npm.cmd", "npm.exe", "npx.cmd", "npx.exe", "node.exe", "node", "yarn.cmd", "pnpm.cmd")
| where InitiatingProcessCommandLine has_any ("postinstall", "preinstall", "install.js")
    or ProcessCommandLine has_any ("postinstall.js", "scripts/postinstall", "scripts\\postinstall")
| where FileName in~ ("node.exe", "node", "cmd.exe", "powershell.exe", "pwsh.exe", "sh", "bash", "curl.exe", "curl")
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    FolderPath
| order by Timestamp desc
```

---

### Query 11 — Detached Hidden Node.js Child Process (DeviceProcessEvents)

**Goal:** Detect a `node.exe` child process launched with hidden-window / detached characteristics that survives the parent npm install — the stager's `.unref()` + `windowsHide=true` background-execution pattern. Higher fidelity than the generic postinstall query.  
**MITRE:** T1027, T1497

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Behavioral hunt — DeviceProcessEvents does not directly expose .unref()/windowsHide flags, so this approximates via parent npm context + node child. Use as a hunt and correlate with tmpdir drop / C2. Tune to reduce IDE/build-agent FPs."
-->

```kql
// node child process spawned in an npm install context (detached-execution approximation)
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("node.exe", "node")
| where InitiatingProcessFileName in~ ("npm.cmd", "npm.exe", "npx.cmd", "npx.exe", "node.exe", "node")
| where InitiatingProcessCommandLine has_any ("install", "postinstall", "preinstall")
| where ProcessCommandLine has_any (".cache", "tmp", "temp", "_init.js")
| project
    Timestamp,
    DeviceName,
    AccountName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    FolderPath
| order by Timestamp desc
```

---

### Query 12 — C2 DNS Resolution via ASIM (ASimDnsActivityLogs)

**Goal:** Detect DNS resolution of the C2 and lure domains across all ASIM-normalized DNS sources (firewalls, DNS servers, EDR). Broader cross-source coverage than MDE-only network events.  
**MITRE:** T1071.001

<!-- cd-metadata
cd_ready: false
adaptation_notes: "ASIM DNS query using summarize — designed for hunting/threat-intel sweeps across normalized DNS sources. For CD, narrow to a single source table or convert to row-level."
-->

```kql
// ASIM DNS: resolve campaign C2 and lure domains
ASimDnsActivityLogs
| where TimeGenerated > ago(30d)
| where DnsQuery has "moika.tech"
    or DnsQuery in~ ("npm.t-in-one.io", "docs.t-in-one.io", "jira.t-in-one.io")
| summarize
    Count = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    Queries = make_set(DnsQuery, 20)
    by SrcIpAddr, Dvc
| order by Count desc
```

---

### Query 13 — C2 DNS via MDE DNS Events (DeviceEvents)

**Goal:** Detect endpoint DNS lookups of the C2/lure domains via MDE's `DnsQueryResponse` action — device-attributed DNS resolution complementing the ASIM query.  
**MITRE:** T1071.001

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CommandAndControl"
title: "DNS lookup of npm dependency-confusion C2/lure domain on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Device resolved the campaign C2 or a lure domain. Correlate with the connection (Query 5) and the initiating npm install. If confirmed, isolate and rotate exposed secrets."
adaptation_notes: "Already row-level. Add DeviceId + ReportId. AdditionalFields parsing of the query name varies by sensor — adjust the field extraction if needed."
-->

```kql
// MDE DNS events: resolve campaign C2 and lure domains
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "DnsQueryResponse"
| where AdditionalFields has "moika.tech"
    or AdditionalFields has_any ("npm.t-in-one.io", "docs.t-in-one.io", "jira.t-in-one.io")
| project
    Timestamp,
    DeviceName,
    ActionType,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    AdditionalFields
| order by Timestamp desc
```

---

### Query 14 — node.exe Anomalous Outbound Connections (DeviceNetworkEvents)

**Goal:** Surface `node.exe` outbound connections to destinations *outside* the common known-good set — a generic hunt for npm-stager C2 that doesn't rely on the specific `oob.moika.tech` IoC. Requires environment tuning.  
**MITRE:** T1071.001, T1041

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Broad hunt with summarize — high FP. node.exe legitimately reaches registries, AI/SaaS APIs, CDNs. Exclusion list must be tuned to your environment's known-good Node egress before any alerting."
-->

```kql
// node.exe reaching uncommon destinations — generic stager-C2 hunt
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("node.exe", "node")
| where ActionType in ("ConnectionSuccess", "ConnectionAttempt")
| where isnotempty(RemoteUrl)
| where RemoteUrl !has "npmjs.org"
    and RemoteUrl !has "yarnpkg"
    and RemoteUrl !has "microsoft.com"
    and RemoteUrl !has "windows.net"
    and RemoteUrl !has "azure"
    and RemoteUrl !has "github"
    and RemoteUrl !has "githubusercontent"
    and RemoteUrl !has "googleapis.com"
    and RemoteUrl !has "openai.com"
    and RemoteUrl !has "anthropic.com"
    and RemoteUrl !has "cloudflare"
    and RemoteUrl !has "localhost"
| summarize
    ConnectionCount = count(),
    Devices = make_set(DeviceName, 10),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by RemoteUrl, RemoteIP
| order by ConnectionCount desc
| take 50
```

---

### Query 15 — CDC Dropped Payload Detection (DeviceCustomFileEvents)

**Goal:** CDC-backed detection of the `._<scope>_init.js` dropped payloads and run-once cache directories. Catches file activity that standard `DeviceFileEvents` may miss when CDC extends collection beyond default thresholds.  
**MITRE:** T1027, T1070.004

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Execution"
title: "CDC: npm dependency-confusion dropped payload {{FileName}} on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "CRITICAL: CDC captured a dropped payload matching the campaign ._<scope>_init.js pattern. The stager fetched and wrote a payload. Isolate, preserve the file, identify the npm install, and rotate exposed secrets."
adaptation_notes: "CDC table — may not exist in all environments (Failed to resolve table = not provisioned). Already row-level with SHA256. Add DeviceId + ReportId. Near-zero FP via the campaign naming regex."
-->

```kql
// CDC: dropped payloads and run-once cache dirs
DeviceCustomFileEvents
| where Timestamp > ago(30d)
| where FileName matches regex @"^\._.*_init\.js$"
    or FolderPath has_any (
        "._cloudplatform-single-spa_init", "._wb-track_init", "._data-science_init",
        "._ce-rwb_init", "._payments-widget_init", "._travel-autotests_init",
        "._t-in-one_init", "._capibar.chat_init", "._sber-ecom-core_init")
| project
    Timestamp,
    DeviceName,
    ActionType,
    FileName,
    FolderPath,
    InitiatingProcessFileName,
    SHA256
| order by Timestamp desc
```

---

### Query 16 — CDC node_modules File Activity Audit (DeviceCustomFileEvents)

**Goal:** Comprehensive CDC audit of file activity within `node_modules`, excluding bundled-app modules and installer-extracted modules. Identifies hosts actively installing packages — exposure scoping for any npm supply-chain campaign — and surfaces `scripts/postinstall.js` writes. Groups by **initiating process** so genuine `npm`/`node`-driven installs are separable from installer extraction noise.  
**MITRE:** T1195.002

> **Tuning note (validated):** A `FolderPath has "node_modules"` match *without* an initiator filter is dominated by **bundled-app extraction** — installers (`svchost.exe`, `setup.exe`, `code-insiders.exe` / VS Code Insiders setup) unpacking their own bundled `node_modules`. In testing this produced tens of thousands of benign `FileCreated` events with **zero** node/npm-initiated activity. The `InitiatingProcessFileName` projection below lets you filter to `node.exe`/`npm`/`npx`/`yarn`/`pnpm` rows for true install activity; the installer/setup exclusions remove the bulk of the noise.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Device-level summarize audit — exposure scoping, not alerting. CDC table may not exist in all environments. Folder-only matching is dominated by installer-extracted bundled node_modules (svchost/setup.exe/code-insiders) — group by InitiatingProcessFileName and filter to node/npm/npx/yarn/pnpm for genuine installs. Extend the bundled-module + installer exclusion lists for IDEs/runtimes in your fleet."
-->

```kql
// CDC: node_modules file activity audit (exposure scoping)
DeviceCustomFileEvents
| where Timestamp > ago(7d)
| where FolderPath has "node_modules"
| where FolderPath !has "WindowsApps"
    and FolderPath !has "Microsoft.GamingApp"
    and FolderPath !has @".vscode\extensions"
    and FolderPath !has @".vscode-insiders\extensions"
// Exclude installer / setup extraction of bundled node_modules (validated FP source)
| where InitiatingProcessFileName !in~ ("svchost.exe", "setup.exe", "msiexec.exe", "trustedinstaller.exe")
    and InitiatingProcessFileName !contains "codesetup"
    and InitiatingProcessFileName !contains "setup-"
| extend IsPackageManagerDriven = InitiatingProcessFileName in~ ("node.exe", "node", "npm.cmd", "npm.exe", "npx.cmd", "npx.exe", "yarn.cmd", "pnpm.cmd")
| summarize
    FileCount = count(),
    ActionTypes = make_set(ActionType, 10),
    SamplePaths = make_set(FolderPath, 20),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by DeviceName, InitiatingProcessFileName, IsPackageManagerDriven
| order by IsPackageManagerDriven desc, FileCount desc
```

---

### Query 17 — CDC AMSI: Campaign Indicators in Script Content (DeviceCustomScriptEvents)

**Goal:** Search AMSI-captured script content for campaign indicators — C2 host, shared secret, scope names, recon env vars — that may appear in any PowerShell/VBScript wrapper invoked by the stager or downstream payload.  
**MITRE:** T1059.001, T1027

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Execution"
title: "CDC AMSI: npm dependency-confusion indicator in script on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "AMSI captured script content containing campaign indicators (C2 host, shared secret, scope names, or recon env vars). Review the full ScriptContent for C2 communication and credential access. Correlate with npm install activity and dropped payloads."
adaptation_notes: "CDC table — may not exist in all environments. AMSI sees PowerShell/VBScript/JScript only, NOT Node.js — value is for PowerShell wrappers, not the JS stager itself. Already row-level. Add DeviceId + ReportId."
-->

```kql
// CDC AMSI: campaign indicators in captured script content
DeviceCustomScriptEvents
| where Timestamp > ago(30d)
| where ScriptContent has_any (
    "oob.moika.tech",
    "l95HdDaz3kQx1Zsg3WxH6HvKANf51RY1",
    "_RECON_ONLY",
    "T_IN_ONE_NO_TELEMETRY",
    "@cloudplatform-single-spa",
    "@sber-ecom-core",
    "@capibar.chat",
    "_init.js")
| project
    Timestamp,
    DeviceName,
    ScriptContentSHA256,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc
```

---

### Query 18 — CDC AMSI: Obfuscated postinstall Patterns (DeviceCustomScriptEvents)

**Goal:** Broader CDC hunt for obfuscator.io-style patterns and suspicious npm-postinstall behaviors in AMSI-captured script content spawned in a node context — string-array encoding, control-flow markers, child-process spawning, HTTP fetch.  
**MITRE:** T1027, T1059.007

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Broad hunt — high FP from legitimate obfuscated/minified scripts and postinstall hooks. CDC table may not exist. Needs environment tuning before alerting."
-->

```kql
// CDC AMSI: obfuscation / suspicious-postinstall patterns in node-context scripts
DeviceCustomScriptEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("node.exe", "node", "npm.cmd", "npm.exe")
    or ScriptContent has_any ("postinstall", "node_modules")
| where ScriptContent has_any (
    "windowsHide",
    ".unref(",
    "os.tmpdir",
    "child_process",
    "_0x",
    "FromBase64String",
    "DownloadString",
    "Invoke-WebRequest")
| project
    Timestamp,
    DeviceName,
    ScriptContentSHA256,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc
| take 50
```

---

### Query 19 — package.json / Lockfile / .npmrc Modifications (DeviceFileEvents)

**Goal:** Surface manifest/lockfile/`.npmrc` writes by npm tooling outside `node_modules` — corroborating evidence of dependency installs. Useful for correlating an install timeline with C2/payload artifacts.  
**MITRE:** T1195.002

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Corroboration/inventory query. Telemetry is sparse — global installs and many flows do not emit per-file package.json events. Use as supporting evidence, not a primary detection."
-->

```kql
// Manifest/lockfile/.npmrc writes by npm tooling
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName in~ ("package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", ".npmrc")
| where InitiatingProcessFileName in~ ("node.exe", "node", "npm.cmd", "npm.exe", "npx.cmd", "npx.exe", "yarn.cmd", "pnpm.cmd")
| where FolderPath !has "node_modules"
| project
    Timestamp,
    DeviceName,
    ActionType,
    FileName,
    FolderPath,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc
```

---

### Query 20 — Campaign Packages in TVM Software Inventory (DeviceTvmSoftwareInventory)

**Goal:** Identify devices whose TVM software inventory references a campaign scope name or inflated version — a longer-lived signal that a malicious package is (or was) present, independent of process-event retention.  
**MITRE:** T1195.002

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Inventory/posture query using summarize. TVM rarely indexes individual npm packages by scope, so coverage is best-effort — absence here does not rule out compromise. No Timestamp column on this table."
-->

```kql
// TVM inventory: campaign scopes / package names / inflated versions
DeviceTvmSoftwareInventory
| where SoftwareName has_any (
    "@cloudplatform-single-spa", "@wb-track", "@data-science", "@ce-rwb",
    "@payments-widget", "@travel-autotests", "@t-in-one", "@capibar.chat", "@sber-ecom-core",
    "svp-baas", "sberpay-widget", "ce-tools-editor", "payments-widget-sdk")
    or SoftwareVersion in ("100.100.100", "99.99.99", "99.99.100", "99.5.7", "99.5.8", "99.0.7")
| summarize
    Devices = make_set(DeviceName, 30),
    Versions = make_set(SoftwareVersion, 20)
    by SoftwareName, SoftwareVendor
| order by SoftwareName asc
```

---

### Query 21 — Cloud Workload Stager / C2 Activity (CloudProcessEvents)

**Goal:** Detect the campaign stager or C2 contact on cloud workloads — CI/CD runners and containers monitored by Defender for Cloud, where npm installs frequently run and credentials are abundant. Covers environments without an MDE agent.  
**MITRE:** T1195.002, T1071.001

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Execution"
title: "Cloud: npm dependency-confusion stager / C2 on cloud workload"
impactedAssets:
  - type: cloudResource
    identifier: azureResourceId
recommendedActions: "CRITICAL: A cloud workload contacted the campaign C2 or ran the stager. CI/CD environments hold high-value secrets — rotate all secrets in the build environment, review pipeline definitions for the malicious dependency/scope, and check connected cloud resources for follow-on access."
adaptation_notes: "CloudProcessEvents requires Defender for Cloud. Schema differs from DeviceProcessEvents: no DeviceName (use AzureResourceId/ContainerName/KubernetesPodName), no InitiatingProcessFileName (use ParentProcessName). Already row-level. Add ReportId. High-volume table — keep the lead filter selective."
-->

```kql
// Cloud workloads: campaign C2 marker or scope+postinstall execution
CloudProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has_any ("oob.moika.tech", "l95HdDaz3kQx1Zsg3WxH6HvKANf51RY1", "_RECON_ONLY")
    or (ProcessCommandLine has "postinstall" and ProcessCommandLine has_any (
        "@cloudplatform-single-spa", "@wb-track", "@t-in-one", "@sber-ecom-core", "@capibar.chat",
        "@ce-rwb", "@payments-widget", "@travel-autotests", "@data-science"))
| project
    Timestamp,
    AzureResourceId,
    ContainerName,
    KubernetesPodName,
    AccountName,
    ProcessCommandLine,
    ProcessCurrentWorkingDirectory,
    ParentProcessName
| order by Timestamp desc
```

---

### Query 22 — ASIM Web Session C2 Detection (_Im_WebSession)

**Goal:** Detect C2 web requests across all ASIM web-session sources (proxies, WAFs, SWGs) by C2 host/URL or the shared-secret value — broad cross-vendor coverage beyond MDE.  
**MITRE:** T1071.001, T1041

> **Note:** ASIM parser functions work via **Advanced Hunting** (not Data Lake MCP — `query_lake` cannot resolve workspace-level functions).

<!-- cd-metadata
cd_ready: false
adaptation_notes: "ASIM parser function _Im_WebSession with summarize — works in AH and portal, NOT via Sentinel Data Lake MCP. Best deployed as a Sentinel Analytics Rule rather than CD."
-->

```kql
// ASIM web sessions: campaign C2 / lure / shared secret
let lookback = 30d;
let ioc_domains = dynamic(["oob.moika.tech", "moika.tech", "npm.t-in-one.io", "docs.t-in-one.io", "jira.t-in-one.io"]);
_Im_WebSession(starttime=todatetime(ago(lookback)), endtime=now())
| where Url has_any (ioc_domains)
    or DstDomain has_any (ioc_domains)
    or HttpUserAgent has "l95HdDaz3kQx1Zsg3WxH6HvKANf51RY1"
| summarize
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    EventCount = count()
    by SrcIpAddr, DstIpAddr, Url, Dvc, EventProduct, EventVendor
| order by EventCount desc
```

---

### Query 23 — ASIM Network Session C2 Detection (_Im_NetworkSession)

**Goal:** Detect C2 connections across all ASIM network-session sources (firewalls, proxies, NDR, NSGs) by C2 domain — cross-vendor coverage for the recon-phase callbacks.  
**MITRE:** T1071.001, T1041

> **Note:** ASIM parser functions work via **Advanced Hunting** (not Data Lake MCP — `query_lake` cannot resolve workspace-level functions).

<!-- cd-metadata
cd_ready: false
adaptation_notes: "ASIM parser function _Im_NetworkSession with summarize — works in AH and portal, NOT via Sentinel Data Lake MCP. Best deployed as a Sentinel Analytics Rule rather than CD. DstIpAddr filtering requires resolving the C2 to current IPs first."
-->

```kql
// ASIM network sessions: campaign C2 / lure domains
let lookback = 30d;
let ioc_domains = dynamic(["oob.moika.tech", "moika.tech", "npm.t-in-one.io", "docs.t-in-one.io", "jira.t-in-one.io"]);
_Im_NetworkSession(starttime=todatetime(ago(lookback)), endtime=now())
| where DstDomain has_any (ioc_domains)
| summarize
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    EventCount = count()
    by SrcIpAddr, DstIpAddr, DstDomain, Dvc, EventProduct, EventVendor
| order by EventCount desc
```

---

### Query 24 — Defender Detection Correlation (AlertInfo)

**Goal:** Surface Defender alerts whose titles match this campaign's detection names and behaviors (`ObfusNpmJs`, suspicious Node.js / detached child / tmpdir-write / npm-lifecycle behaviors). Confirms MDE coverage fired and pivots into incident context.  
**MITRE:** T1195.002, T1027

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Alert-correlation query — surfaces existing Defender alerts, not a new detection. Use for triage/coverage validation. For row-level CD, this is redundant with the underlying MDE detections."
-->

```kql
// Correlate Defender alerts matching campaign detection names / behaviors
AlertInfo
| where Timestamp > ago(30d)
| where Title has_any (
    "ObfusNpmJs",
    "npm lifecycle",
    "detached child process",
    "windowsHide",
    "obfuscated JavaScript",
    "Node.js process",
    "temporary directory by Node",
    "persistence file creation in user cache")
| project
    Timestamp,
    AlertId,
    Title,
    Severity,
    Category,
    AttackTechniques,
    ServiceSource
| order by Timestamp desc
```

---

### Query 25 — npm Ecosystem Exposure Inventory (DeviceProcessEvents)

**Goal:** Full-fleet inventory of node.js/npm ecosystem usage — which devices run node/npm/yarn/pnpm/npx and how. Foundation for assessing the blast radius of this (or any) npm supply-chain campaign and for scoping which assets warrant the higher-fidelity detections.  
**MITRE:** T1195.002

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Fleet inventory query using summarize — exposure reporting, not alerting."
-->

```kql
// Fleet inventory: node.js/npm ecosystem process activity
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("node.exe", "node", "npm.cmd", "npm", "npx.cmd", "npx", "yarn.cmd", "yarn", "pnpm.cmd", "pnpm", "bun.exe", "bun")
| summarize
    ProcessCount = count(),
    Users = make_set(AccountName, 20),
    SampleCommands = make_set(ProcessCommandLine, 30),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by DeviceName, FileName
| order by ProcessCount desc
```
