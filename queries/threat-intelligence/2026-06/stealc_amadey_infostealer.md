# StealC & Amadey — Infostealer + Loader-as-a-Service — Threat Hunts

**Created:** 2026-06-24  
**Platform:** Microsoft Defender XDR  
**Tables:** DeviceFileEvents, DeviceNetworkEvents, DeviceProcessEvents, DeviceRegistryEvents  
**Keywords:** StealC, Amadey, infostealer, loader, malware-as-a-service, MaaS, cybercrime services, nudwee.exe, e079729711, scheduled task, rundll32, cred.dll, clip.dll, plugin, clipper, RunOnce, self-uninstall, RMDIR, Enable RDP, fDenyTSConnections, hidden admin, local administrator, net localgroup, SOCKS proxy, screenshot exfiltration, RC4, GitLab delivery, credential theft, clipboard hijack  
**MITRE:** T1105, T1059.001, T1059.003, T1218.011, T1053.005, T1547.001, T1070.004, T1021.001, T1136.001, T1098, T1115, T1555.003, T1113, T1071.001, T1090, T1041, T1480, TA0011, TA0003  
**Domains:** endpoint  
**Timeframe:** Last 30 days (configurable)  
**Source:** [StealC and Amadey: Breaking down infostealers and the cybercrime services that deliver them (2026-06-24)](https://www.microsoft.com/en-us/security/blog/2026/06/24/stealc-and-amadey-breaking-down-infostealers-and-the-cybercrime-services-that-deliver-them/)

---

## Threat Overview

Microsoft Threat Intelligence details the symbiotic relationship between **StealC** (a widely-sold infostealer) and **Amadey** (a modular C++ loader/backdoor) that delivers it. In one observed chain, threat actors abused a **compromised self-hosted GitLab instance** — a long-established domain with valid TLS certificates — to host and deliver StealC via Amadey, helping the delivery blend in and evade traditional defenses.

The chain begins with the **Amadey first-stage loader**: on execution it creates a mutex to prevent duplicate runs, performs host discovery, and beacons to its HTTP C2 (RC4-encrypted, hex-encoded victim fingerprint). Amadey then copies itself to **`nudwee.exe`** inside a victim-specific folder (`C:\Users\<user>\e079729711` on Win10/11, else `%TEMP%\e079729711`), executes the copy, and registers a **scheduled task** for persistence. Its C2 can push numerous backdoor commands: drop/execute EXE/DLL/MSI/PS1 payloads, download-and-inject, run commands via `cmd.exe`, start/stop a **SOCKS proxy**, capture and exfiltrate **screenshots**, load **`cred.dll`** / **`clip.dll`** plugins via `rundll32.exe` for credential and clipboard theft, install a **VNC** component, **enable RDP** (`fDenyTSConnections=0` + firewall/service changes), **create a hidden local administrator**, and **self-uninstall** via a `RunOnce` key that runs `cmd /C RMDIR /s/q …\e079729711` on reboot. Amadey skips credential/clipboard theft on Russian/Ukrainian/Belarusian keyboard layouts (execution guardrail). Follow-on **StealC** execution communicates with its own separate C2 to harvest browser credentials, cookies, and wallet data.

### TTP Summary
| Capability | TTP |
|---|---|
| Amadey copies to `nudwee.exe` in `e079729711` + scheduled task | Scheduled Task/Job (T1053.005) |
| HTTP C2 beacon (RC4-encrypted victim fingerprint) | Application Layer Protocol: Web (T1071.001) |
| Drop/execute EXE/DLL/MSI/PS1 from C2 | Ingress Tool Transfer (T1105), PowerShell (T1059.001), Command Shell (T1059.003) |
| Load `cred.dll` / `clip.dll` plugins via `rundll32.exe …,Main` | System Binary Proxy Execution: Rundll32 (T1218.011) |
| Credential plugin (`cred.dll`) → browser credential theft (StealC) | Credentials from Web Browsers (T1555.003) |
| Clipboard/clipper plugin (`clip.dll`) | Clipboard Data (T1115) |
| Screenshot capture + exfil to C2 (`?scr=1`) | Screen Capture (T1113), Exfil over C2 (T1041) |
| SOCKS proxy relay | Proxy (T1090) |
| Enable RDP (`fDenyTSConnections=0` + firewall/service) | Remote Services: RDP (T1021.001) |
| Create hidden local admin (`net user /add` + `net localgroup administrators /add`) | Create Account: Local (T1136.001), Account Manipulation (T1098) |
| Self-uninstall via `RunOnce` → `RMDIR /s/q …\e079729711` | Registry Run Keys/RunOnce (T1547.001), File Deletion (T1070.004) |
| Skip stealing on RU/UA/BY keyboard layouts | Execution Guardrails (T1480) |

### ⚠️ Hunt Pitfalls
| Pitfall | Mitigation |
|---|---|
| `schtasks /create`, `net user /add`, and RDP enablement are extremely common admin/IT operations | **Never** alert on these alone — anchor on the Amadey artifact path (`e079729711` / `nudwee.exe`) or correlate with a C2/plugin hit. Bare behavioral queries here are hunt-only |
| `fDenyTSConnections=0` matches every legitimate RDP enablement (GPO, IT tooling, MDM) | Treat the standalone RDP query as low-fidelity hunting; for detection, require co-occurrence with Amadey context or hidden-admin creation on the same host/time window |
| `rundll32.exe` is heavily used by legitimate Windows components | Anchor on the plugin names (`cred.dll`, `clip.dll`) **and** the `Main` export + non-system load path; bare `rundll32` is not huntable |
| Published hashes/C2 rot quickly after disclosure | IOC sweeps are point-in-time. Refresh from current Microsoft TI and run retrospectively in Sentinel Data Lake (>30d) |
| Amadey version churn (5.60–5.87 hashes listed) means new builds won't match old hashes | Pair hash sweeps with the durable behavioral anchors (folder name, plugin loads, self-uninstall) which survive recompilation |
| Region guardrail means some plugin activity is suppressed on RU/UA/BY hosts | Don't treat absence of credential-theft telemetry as absence of infection — the loader/persistence signals still fire |

---

## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [StealC/Amadey file-hash IOC sweep](#query-1-stealcamadey-file-hash-ioc-sweep) | Investigation | `DeviceFileEvents` |
| 2 | [StealC/Amadey C2 connections](#query-2-stealcamadey-c2-connections) | Investigation | `DeviceNetworkEvents` |
| 3 | [Amadey persistence directory / self-copy (`e079729711` / `nudwee.exe`)](#query-3-amadey-persistence-directory--self-copy-e079729711--nudweeexe) | Investigation | `DeviceFileEvents` + multi |
| 4 | [Amadey plugin loading via rundll32 (`cred.dll` / `clip.dll`)](#query-4-amadey-plugin-loading-via-rundll32-creddll--clipdll) | Investigation | `DeviceProcessEvents` |
| 5 | [Amadey self-uninstall (RunOnce → RMDIR of `e079729711`)](#query-5-amadey-self-uninstall-runonce--rmdir-of-e079729711) | Investigation | `DeviceProcessEvents` + `DeviceRegistryEvents` |
| 6 | [Enable RDP via `fDenyTSConnections=0` (hunt-only)](#query-6-enable-rdp-via-fdenytsconnections0-hunt-only) | Investigation | `DeviceProcessEvents` + `DeviceRegistryEvents` |
| 7 | [Hidden local administrator creation](#query-7-hidden-local-administrator-creation) | Investigation | `DeviceProcessEvents` |


## IOC Reference

> All indicators below are transcribed verbatim from the article's *Indicators of compromise* section. C2 URLs are defanged in this table exactly as published (`hxxp`, `[.]`); the hunting queries use the bare registrable domains. **IOCs rot** — refresh from current Microsoft TI before relying on direct-match hunts, and run sweeps in Sentinel Data Lake (>30d) for retrospective coverage.

**File indicators (SHA-256)**

| Indicator | Description |
|---|---|
| `8f32456359f209a63adfd24b94235e1727382ac7f7bb7f2bcaf754e721925b64` | StealC |
| `0215f734867bd71c57ff5c524d8cc670be5b4f1861b2c390cf46d18784a53624` | StealC |
| `2a0f053855da59b3b56812e580d7baeba59fc9493694722aa9e3f121ee3363f1` | StealC |
| `977b33a9b481cf714946b7d386865cd5d284312aa5ecfa0546c197b1003e1bde` | StealC |
| `b7d1f172ff3feafe65d47fd1cbe0cc249316371ae0e1cbe3a7c741c738b3353d` | Amadey 5.87 |
| `9383572a30ae5b76fadd0700fbd7a1aa7b05d0b6c8f9cdaef9b30a3e1f65d57d` | Amadey 5.86 |
| `5f5b25b2e35d404034d0d60975cf1ffbc6f141761ec3f4f15d6f7c6213a056f6` | Amadey 5.80 |
| `98e504cc7125b79eda5491f40b998605a05f4cd968b961aab4cce7beb074fefe` | Amadey 5.78 |
| `30cef3d3d956e83e2c50579cfbe57a49159cccbcc8b0b0422f27d55e1c401ad9` | Amadey 5.77 |
| `8cef760d11d24fc2e9bbd9f770dca5105854f7ece3b0e6948d7c8b7fdd1765ea` | Amadey 5.73 |
| `99507f18c4e61fdb109805404bf6a79ea8ce2fddc590ce48d717e97516ab7e8d` | Amadey 5.70 |
| `1246c5b89ab668c1137f377507bc3e266a98e93248382aa026610ae1e764a497` | Amadey 5.65 |
| `d43c988d6f9cb355497696b580621fb1bdb7b6ed6d90f97520ecf6da5a1a41ff` | Amadey 5.64 |
| `ca4d4c4fc3e5d5cfa922b898f2d7411f03a446dddb139ba45dfd4f8f0018b64f` | Amadey 5.63 |
| `43455f1ff4a623b783da670d052eb77eaaacb0c66a9f1e8508f802bf22e8129e` | Amadey 5.60 |

**Network indicators (C2 URLs, as published)**

| Indicator | Type | Description |
|---|---|---|
| `hxxp://polse[.]us/62ea47cac2534aa18f74.php` | C2 URL | StealC C2 |
| `hxxp://roger99699[.]xyz/425f1faf4b214434b8a3.php` | C2 URL | StealC C2 |
| `hxxp://bluescry[.]com/01f96fd710e905ca2326.php` | C2 URL | StealC C2 |
| `hxxp://secure.controlpanel[.]asia/330311481fe14ab99814.php` | C2 URL | StealC C2 |
| `hxxps://neltron-geltron[.]shop/e396586b99ee49d19cc3.php` | C2 URL | StealC C2 |
| `hxxp://cdntestconnect[.]com/ed54b97a570943999715.php` | C2 URL | StealC C2 |
| `hxxps://bartsen284[.]online/39d9612df78e45b5a4bb.php` | C2 URL | StealC C2 |
| `hxxp://goodpanelforgoodjob[.]com/hg8jjfSr5hy/index.php` | C2 URL | Amadey C2 |
| `hxxp://rebustan[.]top/gd7djkDveE2/index.php` | C2 URL | Amadey C2 |
| `hxxp://svclsc[.]com/ms/index.php` | C2 URL | Amadey C2 |
| `hxxp://microsoft-telemetry[.]at/cvdfnaFJBmC0/index.php` | C2 URL | Amadey C2 |
| `hxxp://spasopro[.]at/Lsge63sd3/index.php` | C2 URL | Amadey C2 |

**Host indicators**

| Indicator | Type | Description |
|---|---|---|
| `nudwee.exe` | File | Amadey self-copy executable |
| `e079729711` | Folder | Amadey persistence directory (`C:\Users\<user>\e079729711` or `%TEMP%\e079729711`) |
| `cred.dll` / `clip.dll` | DLL plugin | Amadey credential / clipboard theft plugins (loaded via `rundll32 …,Main`) |

---

## Query 1: StealC/Amadey file-hash IOC sweep

**Purpose:** Direct SHA-256 sweep across file events for the 15 published StealC and Amadey samples (Amadey 5.60–5.87).  
**Severity:** High  
**MITRE:** T1105
<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Malware"
title: "StealC/Amadey file IOC observed on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "A published StealC or Amadey hash was written/observed. Isolate the device, hunt for Amadey persistence (Queries 3-5) and C2 (Query 2), and rotate any credentials/cookies that may have been harvested. Hashes rot across Amadey builds — refresh from current Microsoft TI / VirusTotal."
adaptation_notes: "Row-level hash match. Add ReportId. Also sweep DeviceProcessEvents.SHA256 and DeviceImageLoadEvents.SHA256 with the same list for execution/load coverage."
-->

```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA256 in (
    "8f32456359f209a63adfd24b94235e1727382ac7f7bb7f2bcaf754e721925b64",
    "0215f734867bd71c57ff5c524d8cc670be5b4f1861b2c390cf46d18784a53624",
    "2a0f053855da59b3b56812e580d7baeba59fc9493694722aa9e3f121ee3363f1",
    "977b33a9b481cf714946b7d386865cd5d284312aa5ecfa0546c197b1003e1bde",
    "b7d1f172ff3feafe65d47fd1cbe0cc249316371ae0e1cbe3a7c741c738b3353d",
    "9383572a30ae5b76fadd0700fbd7a1aa7b05d0b6c8f9cdaef9b30a3e1f65d57d",
    "5f5b25b2e35d404034d0d60975cf1ffbc6f141761ec3f4f15d6f7c6213a056f6",
    "98e504cc7125b79eda5491f40b998605a05f4cd968b961aab4cce7beb074fefe",
    "30cef3d3d956e83e2c50579cfbe57a49159cccbcc8b0b0422f27d55e1c401ad9",
    "8cef760d11d24fc2e9bbd9f770dca5105854f7ece3b0e6948d7c8b7fdd1765ea",
    "99507f18c4e61fdb109805404bf6a79ea8ce2fddc590ce48d717e97516ab7e8d",
    "1246c5b89ab668c1137f377507bc3e266a98e93248382aa026610ae1e764a497",
    "d43c988d6f9cb355497696b580621fb1bdb7b6ed6d90f97520ecf6da5a1a41ff",
    "ca4d4c4fc3e5d5cfa922b898f2d7411f03a446dddb139ba45dfd4f8f0018b64f",
    "43455f1ff4a623b783da670d052eb77eaaacb0c66a9f1e8508f802bf22e8129e")
| project Timestamp, DeviceName, FileName, FolderPath, SHA256,
    InitiatingProcessFileName, InitiatingProcessAccountName, DeviceId, ReportId
| sort by Timestamp desc
```

**Expected results:** 0 in an unaffected environment. A match is a direct compromise indicator.

---

## Query 2: StealC/Amadey C2 connections

**Purpose:** Network IOC sweep for the 12 published StealC and Amadey C2 domains.  
**Severity:** High  
**MITRE:** T1071.001, T1041
<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CommandAndControl"
title: "Connection to StealC/Amadey C2 from {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Device contacted a published StealC/Amadey C2 domain. Isolate, identify the initiating process, and hunt for Amadey persistence (Queries 3-5) and plugin loads (Query 4). Domains rot — confirm against current Microsoft TI."
adaptation_notes: "Row-level URL/domain match. Add DeviceId + ReportId. Refresh the domain list periodically."
-->

```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ("polse.us", "roger99699.xyz", "bluescry.com",
    "secure.controlpanel.asia", "neltron-geltron.shop", "cdntestconnect.com",
    "bartsen284.online", "goodpanelforgoodjob.com", "rebustan.top",
    "svclsc.com", "microsoft-telemetry.at", "spasopro.at")
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort,
    InitiatingProcessFileName, InitiatingProcessCommandLine, DeviceId, ReportId
| sort by Timestamp desc
```

**Expected results:** 0 expected (post-disclosure infrastructure). Any hit is a high-confidence C2 indicator.

---

## Query 3: Amadey persistence directory / self-copy (`e079729711` / `nudwee.exe`)

**Purpose:** Detects Amadey's durable persistence anchor — the victim-specific `e079729711` folder, the `nudwee.exe` self-copy, and any scheduled task referencing them. This anchor survives Amadey recompilation (unlike the hashes).  
**Severity:** High  
**MITRE:** T1053.005, T1547.001
<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Persistence"
title: "Amadey persistence artifact on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "An Amadey persistence artifact (e079729711 folder, nudwee.exe, or a scheduled task referencing them) was observed. Isolate, remove the scheduled task and folder after triage, and hunt for plugin loads (Query 4) and C2 (Query 2)."
adaptation_notes: "Already anchored on campaign-specific artifacts — low FP. Union output; for CD, project DeviceId + ReportId on each branch and dedup. The e079729711 folder name and nudwee.exe are durable behavioral anchors."
-->

```kql
union
 (DeviceFileEvents
    | where Timestamp > ago(30d)
    | where FileName =~ "nudwee.exe" or FolderPath has "e079729711"
    | project Timestamp, DeviceName, Source = "FileEvent", FileName, FolderPath,
        Detail = strcat(InitiatingProcessFileName, " | ", InitiatingProcessCommandLine), DeviceId, ReportId),
 (DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName =~ "nudwee.exe" or FolderPath has "e079729711" or ProcessCommandLine has "e079729711"
    | project Timestamp, DeviceName, Source = "ProcessEvent", FileName, FolderPath,
        Detail = ProcessCommandLine, DeviceId, ReportId),
 (DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName =~ "schtasks.exe" and ProcessCommandLine has "/create" and ProcessCommandLine has_any ("nudwee", "e079729711")
    | project Timestamp, DeviceName, Source = "SchedTask", FileName, FolderPath,
        Detail = ProcessCommandLine, DeviceId, ReportId)
| sort by Timestamp desc
```

**Expected results:** 0 expected. The `e079729711` folder name and `nudwee.exe` are campaign-specific.

---

## Query 4: Amadey plugin loading via rundll32 (`cred.dll` / `clip.dll`)

**Purpose:** Detects Amadey loading its credential-theft (`cred.dll`) and clipboard-theft (`clip.dll`) plugins through `rundll32.exe …,Main`.  
**Severity:** High  
**MITRE:** T1218.011, T1555.003, T1115
<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CredentialAccess"
title: "Amadey credential/clipboard plugin loaded on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "rundll32 loaded an Amadey cred.dll/clip.dll plugin (Main export) — active credential or clipboard theft. Isolate, rotate credentials harvested from the host, and hunt for C2 (Query 2) and StealC follow-on (Query 1)."
adaptation_notes: "Row-level. Add DeviceId + ReportId. The cred.dll/clip.dll + Main combination is specific; if legitimate software uses identically named DLLs, additionally require a non-System32 load path or pair with C2."
-->

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "rundll32.exe"
| where ProcessCommandLine has_any ("cred.dll", "clip.dll")
| where ProcessCommandLine has "Main"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessCommandLine, DeviceId, ReportId
| sort by Timestamp desc
```

**Expected results:** 0 expected. Investigate any hit; if a benign product loads identically named DLLs, add a non-System32 path constraint or require C2 co-occurrence.

---

## Query 5: Amadey self-uninstall (RunOnce → RMDIR of `e079729711`)

**Purpose:** Detects Amadey's anti-forensic self-removal — a `RunOnce` registry entry or command that runs `cmd /C RMDIR /s/q …\e079729711` to delete the malware folder on reboot.  
**Severity:** High  
**MITRE:** T1070.004, T1547.001
<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "DefenseEvasion"
title: "Amadey self-uninstall artifact on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "An Amadey self-uninstall command targeting the e079729711 folder was observed — the actor may be cleaning up. Preserve forensic artifacts immediately, isolate, and reconstruct the full chain before the folder is deleted on reboot."
adaptation_notes: "Row-level. Add DeviceId + ReportId. Anchored on the e079729711 folder name — campaign-specific, low FP. Covers both the process command line and the RunOnce registry value."
-->

```kql
union
 (DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where ProcessCommandLine has "RMDIR" and ProcessCommandLine has "e079729711"
    | project Timestamp, DeviceName, Source = "Process", Detail = ProcessCommandLine, DeviceId, ReportId),
 (DeviceRegistryEvents
    | where Timestamp > ago(30d)
    | where RegistryKey has "RunOnce"
    | where RegistryValueData has "e079729711"
    | project Timestamp, DeviceName, Source = "RunOnce", Detail = RegistryValueData, DeviceId, ReportId)
| sort by Timestamp desc
```

**Expected results:** 0 expected. The `e079729711` reference makes this campaign-specific.

---

## Query 6: Enable RDP via `fDenyTSConnections=0` (hunt-only)

**Purpose:** Surfaces hosts where Remote Desktop was enabled by setting `fDenyTSConnections=0` — one of Amadey's backdoor commands. **This is a low-fidelity hunting query**: legitimate IT/GPO/MDM RDP enablement matches it. Use only correlated with Amadey context.  
**Severity:** Low (hunt-only)  
**MITRE:** T1021.001
<!-- cd-metadata
cd_ready: false
adaptation_notes: "NOT suitable as a standalone detection — fDenyTSConnections=0 fires on every legitimate RDP enablement (GPO, IT tooling, MDM). For custom detection, require co-occurrence on the same device/time window with an Amadey artifact (e079729711 / nudwee.exe), a hidden-admin creation (Query 7), or a C2 hit (Query 2). Hunt-only as written."
-->

```kql
union
 (DeviceRegistryEvents
    | where Timestamp > ago(30d)
    | where RegistryValueName == "fDenyTSConnections" and RegistryValueData == "0"
    | project Timestamp, DeviceName, Source = "Registry",
        Detail = strcat(InitiatingProcessFileName, " set fDenyTSConnections=0"), DeviceId),
 (DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where ProcessCommandLine has "fDenyTSConnections"
        and ProcessCommandLine has_any ("0x0", " 0 ", "/d 0")
    | project Timestamp, DeviceName, Source = "Process", Detail = ProcessCommandLine, DeviceId)
| sort by Timestamp desc
```

**Expected results:** Benign RDP enablement by IT/GPO/MDM tooling will match this query — that is expected. Triage by correlating each host/time with Amadey artifacts (Query 3), hidden-admin creation (Query 7), or C2 (Query 2); investigate only correlated hits.

---

## Query 7: Hidden local administrator creation

**Purpose:** Detects Amadey's `create hidden admin` command — creating a local account and adding it to the Administrators group. Pair with Amadey context for high confidence.  
**Severity:** Medium  
**MITRE:** T1136.001, T1098
<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Persistence"
title: "Local admin account creation on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "A local account was added to the Administrators group via net.exe. Confirm whether the account creation is sanctioned IT activity; if not, isolate and correlate with Amadey artifacts (Query 3) and C2 (Query 2). Disable the rogue account and review for privilege escalation."
adaptation_notes: "Row-level. Add DeviceId + ReportId. net localgroup administrators /add is the higher-signal branch; net user /add alone can be benign IT activity, so consider scoping to the localgroup-administrators branch or pairing with Amadey context to reduce FPs. Localgroup names are localized — extend the list for non-English builds."
-->

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("net.exe", "net1.exe")
| where (ProcessCommandLine has "localgroup"
            and ProcessCommandLine has_any ("administrators", "administrateure", "administrateurs", "administradores", "administratoren")
            and ProcessCommandLine has "/add")
    or (ProcessCommandLine has "user" and ProcessCommandLine has "/add")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessCommandLine, DeviceId, ReportId
| sort by Timestamp desc
```

**Expected results:** Low volume. Legitimate IT account provisioning can match the `net user /add` branch — validate against change records; the `net localgroup administrators /add` branch is higher-signal. Correlate with Amadey artifacts for confirmation.

---

## General Tuning Notes

1. **IOC refresh.** Every hash/C2 here is point-in-time from the 2026-06-24 disclosure. Amadey is sold and rebuilt frequently (versions 5.60–5.87 are already listed), so new builds will evade the hash sweep — lean on the durable behavioral anchors (Queries 3–5) which key on the `e079729711` folder, `nudwee.exe`, plugin names, and the self-uninstall pattern. For retrospective coverage beyond 30 days, run the IOC sweeps in **Sentinel Data Lake** (`mcp_sentinel-data_query_lake`), changing `Timestamp` → `TimeGenerated` for the Device* tables.
2. **Behavioral noise discipline.** `schtasks /create`, `net user /add`, `rundll32.exe`, and `fDenyTSConnections=0` are all high-volume legitimate operations. This campaign deliberately **does not** ship bare versions of those queries — every behavioral hunt here is either anchored on a campaign-specific artifact (Queries 3–5, 4's plugin names) or explicitly flagged hunt-only requiring correlation (Query 6). When adapting to custom detections, preserve those anchors.
3. **Correlation > single signals.** The strongest detection is co-occurrence: an Amadey persistence artifact (Query 3) plus a plugin load (Query 4) or C2 hit (Query 2) on the same device within a short window. Consider a scheduled hunt that joins these on `DeviceId` for an alert-grade signal.
4. **Region guardrail.** Amadey suppresses credential/clipboard theft on Russian/Ukrainian/Belarusian keyboard layouts, so the absence of Query 4 hits does not rule out infection — the loader and persistence signals (Queries 3, 5) still fire.
5. **CD-readiness summary.** Queries 1–5 and 7 are row-level and suitable for custom detections (add `DeviceId` + `ReportId`, then apply the detection-authoring Query Adaptation Checklist). Query 6 is `cd_ready: false` (RDP enablement is too common standalone) — use it for hunting or gate it behind Amadey correlation.

---

## References
- Microsoft Threat Intelligence — [StealC and Amadey: Breaking down infostealers and the cybercrime services that deliver them](https://www.microsoft.com/en-us/security/blog/2026/06/24/stealc-and-amadey-breaking-down-infostealers-and-the-cybercrime-services-that-deliver-them/)
- MITRE ATT&CK — [T1053.005 Scheduled Task](https://attack.mitre.org/techniques/T1053/005/), [T1218.011 Rundll32](https://attack.mitre.org/techniques/T1218/011/), [T1136.001 Create Account: Local](https://attack.mitre.org/techniques/T1136/001/), [T1021.001 Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001/), [T1070.004 File Deletion](https://attack.mitre.org/techniques/T1070/004/)
- Companion file: [`queries/threat-intelligence/2026-02/infostealer_hunting_campaign.md`](../2026-02/infostealer_hunting_campaign.md)
