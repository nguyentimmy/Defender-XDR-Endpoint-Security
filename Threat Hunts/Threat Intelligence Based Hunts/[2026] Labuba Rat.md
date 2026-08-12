
# 🎭 LabubaRAT Hunt — NVIDIA Masquerade

**Threat hunt for LabubaRAT, a Rust-based RAT that impersonates NVIDIA software to blend into normal endpoint activity.**

---

## 🎯 Purpose

LabubaRAT ships as `nvidia-sysruntime.exe` with faked NVIDIA version metadata, establishing persistence and remote access while looking like a legitimate GPU service.

It's a **MaaS-style implant** — one compiled binary, configured at runtime via command-line arguments rather than hardcoded C2. That means the operator renames it and rotates infrastructure trivially. A hunt built on the filename alone goes blind on the next campaign.

This query covers the filename **and** the artifacts the operator can't easily change.

---

## 🔍 What it hunts

| # | Section | Rename-resistant |
| --- | --- | --- |
| 1 | Known binary (`nvidia-sysruntime.exe`) | ❌ |
| 2 | 🧬 **NVIDIA metadata masquerade** — claims NVIDIA, runs outside NVIDIA paths | ✅ |
| 3 | ⚙️ Runtime config args (`ZM_*` vars, `--b <base64>` blob) | ✅ |
| 4 | 📁 Artifacts (`nvctr_sys.db`, `nvidia_container.pdb`, `wupd_*.js`) | ✅ |
| 5 | 🔑 HKCU Run persistence (NVIDIA-named or Base64 autorun) | ✅ |
| 6 | 📡 C2 contact + NVIDIA-named process beaconing | ✅ |
| 7 | 🌿 Child processes — shells, script hosts, recon, EDR discovery | ⚠️ Partial |

---

## ⭐ Highest-value section

**Section 2** is the one to deploy as a standing rule. Any binary claiming NVIDIA vendor identity while executing from `%TEMP%`, `%APPDATA%`, or a downloads folder is anomalous regardless of its filename — durable logic that survives a recompile.

**Section 7** deserves attention when it flags security-product discovery: that's the implant fingerprinting your defenses before the operator decides how to proceed. Treat as hands-on-keyboard and isolate.

---

## 🧭 Scoping

Set the lookback to **45 days** for the initial retro-hunt — the sample carries a June compile timestamp and the associated C2 infrastructure went live in early June, so a 7-day window misses the campaign entirely. Drop to 7 days for ongoing scheduled hunting.

---

## 🔍 KQL

Want to simplify things to confirm if the known binary is running on any endpoint? Run this KQL to confirm.
```
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "nvidia-sysruntime.exe"
| project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine, SHA256
| sort by Timestamp desc
```

If `"nvidia-sysruntime.exe"` is found, then can run this advanced hunting query to search for potential NVDIA RAT processes. 
```
// ============================================================
// LABUBARAT - NVIDIA Masquerade RAT Hunt (Rust/MaaS)
// ============================================================
// MITRE ATT&CK:
//   Tactic:    Defense Evasion, Persistence, Command and Control,
//              Execution, Collection, Discovery
//   Technique: T1036.005 - Masquerading: Match Legitimate Name or Location
//              T1547.001 - Boot or Logon Autostart: Registry Run Keys
//              T1059.001 - Command and Scripting Interpreter: PowerShell
//              T1059.007 - Command and Scripting Interpreter: JavaScript
//              T1071.004 - Application Layer Protocol: DNS (tunneling)
//              T1090     - Proxy (SOCKS5)
//              T1113     - Screen Capture
//              T1518.001 - Software Discovery: Security Software Discovery
//              T1027     - Obfuscated Files or Information (Base64 config)
// ============================================================
// Hunts LabubaRAT (Blackpoint APG, Jul 2026) across 7 surfaces: the known
// binary, NVIDIA metadata masquerade (rename-resistant), Base64/ZM_ runtime
// config args, nvctr_sys.db + wupd_ artifacts, HKCU Run persistence, C2
// contact, and spawned child processes. The binary is a reusable MaaS-style
// implant configured at runtime, so it renames trivially - sections 2-6 are
// the durable signals; section 1 alone will go blind.
// NOTE: set LookbackTime to 45d for the initial retro-hunt (June compile
// timestamp, C2 infra live from early June), then drop to 7d for ongoing.
// ============================================================
let LookbackTime = 7d;
let KnownBinary = "nvidia-sysruntime.exe";
let C2Domains = dynamic(["pipicka.xyz"]);
let C2IPs = dynamic(["213.183.55.90"]);
// Legitimate NVIDIA install locations - NVIDIA-branded code outside these is suspect
let LegitNvidiaPaths = dynamic([
    "\\Program Files\\NVIDIA Corporation\\",
    "\\Program Files (x86)\\NVIDIA Corporation\\",
    "\\ProgramData\\NVIDIA Corporation\\",
    "\\ProgramData\\NVIDIA\\",
    "\\Windows\\System32\\DriverStore\\FileRepository\\",
    "\\Program Files\\NVIDIA GPU Computing Toolkit\\"
]);
// Faked version-info strings the sample uses to sell the NVIDIA identity
let NvidiaMetaStrings = dynamic([
    "NVIDIA Container Runtime Monitor",
    "NVIDIA Container Toolkit",
    "NVIDIA Container Runtime"
]);
union isfuzzy=true
// ============================================================
// 1. KNOWN BINARY BY NAME (will go stale - see sections 2-6)
// ============================================================
(
    DeviceProcessEvents
    | where Timestamp > ago(LookbackTime)
    | where FileName =~ KnownBinary
        or ProcessVersionInfoOriginalFileName =~ KnownBinary
        or ProcessVersionInfoInternalFileName =~ KnownBinary
    | extend Technique = "🔴 LabubaRAT Known Binary",
             RiskScore = 10,
             Detail = substring(strcat("Path: ", FolderPath, " | Cmd: ", ProcessCommandLine), 0, 300)
    | project Timestamp, Technique, RiskScore, DeviceName,
              AccountName, ProcessName = FileName, Detail, SHA256
),
// ============================================================
// 2. NVIDIA METADATA MASQUERADE (rename-resistant)
//    Claims NVIDIA identity but runs from a non-NVIDIA path
// ============================================================
(
    DeviceProcessEvents
    | where Timestamp > ago(LookbackTime)
    | where ProcessVersionInfoCompanyName has "NVIDIA"
        or ProcessVersionInfoProductName has_any (NvidiaMetaStrings)
        or ProcessVersionInfoFileDescription has_any (NvidiaMetaStrings)
        or ProcessVersionInfoInternalFileName has "nvidia_container"
    | where not(FolderPath has_any (LegitNvidiaPaths))
    | extend Technique = "🔴 NVIDIA Masquerade (Non-NVIDIA Path)",
             RiskScore = 9,
             Detail = substring(strcat("Claims: ", ProcessVersionInfoCompanyName, " / ",
                             ProcessVersionInfoProductName, " | Running from: ", FolderPath), 0, 300)
    | project Timestamp, Technique, RiskScore, DeviceName,
              AccountName, ProcessName = FileName, Detail, SHA256
),
// ============================================================
// 3. RUNTIME CONFIG ARGS (--b Base64 blob / ZM_ env vars)
// ============================================================
(
    DeviceProcessEvents
    | where Timestamp > ago(LookbackTime)
    | extend CmdArgs = replace_regex(ProcessCommandLine, @'(?i)^\s*"?[^"]*?\.exe"?', "")
    | where CmdArgs has_any (
        "ZM_SERVER", "ZM_ORG", "ZM_KEY", "ZM_GROUP",
        "ZM_DEVICE", "ZM_DNS", "ZM_INTERVAL"
    )
        or CmdArgs matches regex @"\s--?b\s+[A-Za-z0-9+/=]{40,}"
        or CmdArgs has_any ("luxespa", "vip-chair", "LabubaPanel")
    | extend Technique = "🔴 LabubaRAT Runtime Config Args",
             RiskScore = 9,
             Detail = substring(CmdArgs, 0, 300)
    | project Timestamp, Technique, RiskScore, DeviceName,
              AccountName, ProcessName = FileName, Detail, SHA256
),
// ============================================================
// 4. RUNTIME ARTIFACTS (nvctr_sys.db SQLite / wupd_ JS temp files)
// ============================================================
(
    DeviceFileEvents
    | where Timestamp > ago(LookbackTime)
    | where FileName =~ "nvctr_sys.db"
        or FileName startswith "nvctr_sys"
        or FileName =~ "nvidia_container.pdb"
        or (FileName startswith "wupd_"
            and (FileName endswith ".js" or FileName endswith ".jse"
                 or FileName endswith ".vbs" or FileName endswith ".wsf"))
    | extend Technique = "🔴 LabubaRAT Runtime Artifact",
             RiskScore = 10,
             Detail = substring(strcat("File: ", FileName, " | Path: ", FolderPath,
                             " | By: ", InitiatingProcessFileName), 0, 300)
    | project Timestamp, Technique, RiskScore, DeviceName,
              AccountName = InitiatingProcessAccountName,
              ProcessName = InitiatingProcessFileName, Detail, SHA256
),
// ============================================================
// 5. HKCU RUN PERSISTENCE (NVIDIA-named or Base64 autorun)
// ============================================================
(
    DeviceRegistryEvents
    | where Timestamp > ago(LookbackTime)
    | where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
    | where RegistryKey has "CurrentVersion\\Run"
    | where RegistryValueData has_any ("nvidia-sysruntime", "nvctr", "ZM_")
        or RegistryValueName has_any ("NVIDIAContainer", "nvidia-sysruntime", "NvContainerMonitor")
        or (RegistryValueData has "nvidia" and not(RegistryValueData has_any (LegitNvidiaPaths)))
        or RegistryValueData matches regex @"\s--?b\s+[A-Za-z0-9+/=]{40,}"
    | extend Technique = "🔴 LabubaRAT HKCU Run Persistence",
             RiskScore = 9,
             Detail = substring(strcat("Key: ", RegistryKey, "\\", RegistryValueName,
                             " | Data: ", RegistryValueData), 0, 300)
    | project Timestamp, Technique, RiskScore, DeviceName,
              AccountName = InitiatingProcessAccountName,
              ProcessName = InitiatingProcessFileName, Detail, SHA256 = ""
),
// ============================================================
// 6. C2 CONTACT (pipicka[.]xyz / NVIDIA-named proc beaconing)
// ============================================================
(
    DeviceNetworkEvents
    | where Timestamp > ago(LookbackTime)
    | where RemoteUrl has_any (C2Domains)
        or RemoteIP in (C2IPs)
        or (InitiatingProcessFileName =~ KnownBinary and RemoteIPType == "Public")
        or (InitiatingProcessFileName has "nvidia"
            and RemoteIPType == "Public"
            and not(InitiatingProcessFolderPath has_any (LegitNvidiaPaths)))
    | extend IsNamedIOC = RemoteUrl has_any (C2Domains) or RemoteIP in (C2IPs)
    | extend Technique = iff(IsNamedIOC,
                             "🔴 LabubaRAT C2 Contact (named IOC)",
                             "🟠 NVIDIA-Named Process Beaconing"),
             RiskScore = iff(IsNamedIOC, 10, 7),
             Detail = substring(strcat("Remote: ", RemoteUrl, " | IP: ", RemoteIP, ":", RemotePort,
                             " | By: ", InitiatingProcessFileName), 0, 300)
    | project Timestamp, Technique, RiskScore, DeviceName,
              AccountName = InitiatingProcessAccountName,
              ProcessName = InitiatingProcessFileName, Detail,
              SHA256 = InitiatingProcessSHA256
),
// ============================================================
// 7. CHILD PROCESSES SPAWNED (classified)
// ============================================================
(
    DeviceProcessEvents
    | where Timestamp > ago(LookbackTime)
    | where InitiatingProcessFileName =~ KnownBinary
        or (InitiatingProcessVersionInfoCompanyName has "NVIDIA"
            and not(InitiatingProcessFolderPath has_any (LegitNvidiaPaths)))
    | extend CmdArgs = replace_regex(ProcessCommandLine, @'(?i)^\s*"?[^"]*?\.exe"?', "")
    | extend
        IsShellExec  = FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe"),
        IsScriptHost = FileName in~ ("wscript.exe", "cscript.exe", "mshta.exe"),
        IsRecon      = CmdArgs has_any (
            "whoami", "systeminfo", "net user", "net group",
            "nltest", "ipconfig", "tasklist", "wmic",
            "Get-MpComputerStatus", "Get-CimInstance"
        ),
        IsEdrDiscovery = CmdArgs has_any (
            "crowdstrike", "sentinel", "defender", "carbonblack",
            "cylance", "sophos", "mcafee", "falcon"
        )
    | extend Technique = case(
        IsEdrDiscovery, "🔴 LabubaRAT -> Security Product Discovery",
        IsScriptHost,   "🔴 LabubaRAT -> Script Host (JS module)",
        IsShellExec,    "🔴 LabubaRAT -> Shell/PowerShell Execution",
        IsRecon,        "🟠 LabubaRAT -> Host Recon",
        "🟠 LabubaRAT Child Process"
    )
    | extend RiskScore = iff(IsEdrDiscovery, 10, 9),
             Detail = substring(strcat("Spawned: ", FileName, " | Cmd: ", CmdArgs), 0, 300)
    | project Timestamp, Technique, RiskScore, DeviceName,
              AccountName, ProcessName = FileName, Detail, SHA256
)
// ============================================================
// CONSOLIDATE & SCORE
// ============================================================
| extend Severity = case(
    RiskScore >= 9, "🔴 Critical",
    RiskScore >= 7, "🟠 High",
    "🟡 Medium"
)
| summarize
    FirstSeen       = min(Timestamp),
    LastSeen        = max(Timestamp),
    OccurrenceCount = count(),
    Details         = make_set(Detail, 3),
    Hashes          = make_set(SHA256, 3)
    by Technique, Severity, RiskScore, DeviceName, AccountName, ProcessName
| project
    FirstSeen,
    Severity,
    OccurrenceCount,
    Technique,
    DeviceName,
    AccountName,
    ProcessName,
    Details,
    Hashes,
    RiskScore,
    LastSeen
| extend
    timestamp           = FirstSeen,
    HostCustomEntity    = DeviceName,
    AccountCustomEntity = AccountName
| sort by RiskScore desc, LastSeen desc
```

---

## 📚 Reference

Blackpoint Cyber APG, July 2026. MITRE ATT&CK mappings are in the query header (T1036.005, T1547.001, T1059.001/.007, T1071.004, T1090, T1113, T1518.001, T1027).
