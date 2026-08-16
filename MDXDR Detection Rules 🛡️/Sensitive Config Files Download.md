# 🔐 Sensitive Config Exfil — Malicious IP Correlation

**Correlates the download of credential files and network-device configs with connections to known-malicious infrastructure inside a 10-minute window.**

---

## 🎯 Purpose

A credential file appearing on disk is common. A connection to a botnet C2 is alarming but often isolated. **Both on the same host within ten minutes** is a specific, high-confidence pattern: someone is pulling secrets and moving them out.

This hunt requires that temporal correlation rather than alerting on either half alone, which is what keeps it precise enough to act on immediately.

---

## 🗂️ File categories

Matches are classified so triage knows what was taken:

| Category | Covers |
| --- | --- |
| 🔑 **Credential / Secret** | `.env`, `.pem`, `.key`, `.pfx`, `.p12`, `.kdbx`, `.ppk`, `.ovpn`, `.rdp` |
| ⚙️ **General Config** | `.config`, `.conf`, `.cfg`, `.ini` |

**Firewall configs are treated as top severity alongside credentials.** A FortiGate backup contains the full ruleset, VPN definitions, hashed local accounts, and often pre-shared keys — everything needed to map the perimeter and find a way through it.

---

## 🔍 How it works

| Step | Logic |
| --- | --- |
| 1️⃣ | Build a unified malicious-IP set from Sentinel TI + Feodo C2 + SSLBL + Blocklist.de |
| 2️⃣ | Find `DeviceNetworkEvents` connections to those IPs from browsers, PowerShell, or transfer LOLBins |
| 3️⃣ | Join `DeviceFileEvents` on device for sensitive file creation or download |
| 4️⃣ | Require the two events within **600 seconds** of each other |
| 5️⃣ | Exclude Microsoft system paths where config files legitimately churn |
| 6️⃣ | Classify, score, dedupe |

The `datetime_diff` window is the core of the detection — without it this is just two noisy signals in the same table.

---

## 🌐 Feeds

| Feed | Signal |
| --- | --- |
| **Sentinel TI** | Your own curated indicators |
| **Feodo Tracker** | Active botnet C2 |
| **SSLBL** | Malicious SSL certificate IPs |
| **Blocklist.de** | Known attacking IPs |

---

## 🧹 Noise handling

Two exclusions do the heavy lifting:

**System paths** — `\ProgramData\Microsoft\`, `\Windows\AppRepository\`, `\Microsoft\Diagnosis\`, WinSxS, and servicing. Windows writes `.config` and `.ini` files in these constantly as telemetry and component churn.

**Named application configs** — specific vendor config filenames that appear routinely and carry no secrets.

Both lists are environment-specific and expected to grow as you tune.

---

## 🔍 KQL


```
// ============================================================
// SENSITIVE CONFIG EXFIL - Malicious IP Correlation
// ============================================================
// MITRE ATT&CK:
//   Tactic:    Exfiltration, Collection, Credential Access
//   Technique: T1041 - Exfiltration Over C2 Channel
//              T1005 - Data from Local System
//              T1552.001 - Unsecured Credentials: Credentials In Files
//              T1602 - Data from Configuration Repository
// ============================================================
// Correlates downloads of credential and config files with connections to
// known malicious IPs (Sentinel TI + abuse.ch Feodo C2, SSLBL,
// Blocklist.de) within a 10-minute window.
// ============================================================
let LookbackTime = 14d;
let TI_IPs = ThreatIntelligenceIndicator
    | where TimeGenerated > ago(30d)
    | where Active == true
    | where isnotempty(NetworkIP)
    | distinct NetworkIP;
let Feodo_IPs = materialize(
    externaldata(Indicator:string)
    [@"https://feodotracker.abuse.ch/downloads/ipblocklist.txt"]
    with (format="txt")
    | where Indicator matches regex @"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    | distinct Indicator
);
let SSLBL_IPs = materialize(
    externaldata(Indicator:string)
    [@"https://sslbl.abuse.ch/blacklist/sslipblacklist.txt"]
    with (format="txt")
    | where Indicator matches regex @"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    | distinct Indicator
);
let Blocklist_IPs = materialize(
    externaldata(Indicator:string)
    [@"https://lists.blocklist.de/lists/all.txt"]
    with (format="txt")
    | where Indicator matches regex @"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    | distinct Indicator
);
let MaliciousIPs = materialize(
    union
        (TI_IPs | project MalIP = NetworkIP),
        (Feodo_IPs | project MalIP = Indicator),
        (SSLBL_IPs | project MalIP = Indicator),
        (Blocklist_IPs | project MalIP = Indicator)
    | distinct MalIP
);
let SystemPaths = dynamic([
    "\\ProgramData\\Microsoft\\",
    "\\Windows\\AppRepository\\",
    "\\Microsoft\\Diagnosis\\",
    "\\Windows\\System32\\config\\",
    "\\Program Files\\WindowsApps\\",
    "\\Windows\\WinSxS\\",
    "\\Windows\\servicing\\"
]);
DeviceNetworkEvents
| where Timestamp > ago(LookbackTime)
| where RemoteIP in (MaliciousIPs)
| where InitiatingProcessFileName in~ (
    "chrome.exe", "msedge.exe", "firefox.exe",
    "brave.exe", "opera.exe", "tor.exe", "torbrowser.exe",
    "powershell.exe", "pwsh.exe",
    "curl.exe", "wget.exe", "certutil.exe", "bitsadmin.exe"
)
| join kind=inner (
    DeviceFileEvents
    | where Timestamp > ago(LookbackTime)
    | where ActionType in ("FileCreated", "FileDownloaded")
    | where
        // --- Credential / secret files ---
        FileName endswith ".env"
        or FileName endswith ".pem"
        or FileName endswith ".key"
        or FileName endswith ".pfx"
        or FileName endswith ".p12"
        or FileName endswith ".kdbx"
        or FileName endswith ".ppk"
        or FileName endswith ".ovpn"
        or FileName endswith ".rdp"
        // --- General config files ---
        or FileName endswith ".config"
        or FileName endswith ".conf"
        or FileName endswith ".cfg"
        or FileName endswith ".ini"
    | where FileName !in~ (
        ".ADOBE_WEBVIEW_FLAGS_SERVER.CONFIG",
        "ACSLEng.cfg",
        "LogTransport2.cfg",
        "STDeploy.exe.config"
    )
    | extend FileCategory = case(
        FileName endswith ".env" or FileName endswith ".pem" or FileName endswith ".key"
            or FileName endswith ".pfx" or FileName endswith ".p12"
            or FileName endswith ".kdbx" or FileName endswith ".ppk"
            or FileName endswith ".ovpn" or FileName endswith ".rdp", "🔑 Credential/Secret",
        "⚙️ General Config"
    )
    | project
        FileTimestamp = Timestamp,
        DeviceName,
        FileName,
        FolderPath,
        FileCategory,
        FileSHA256 = SHA256
) on DeviceName
| where abs(datetime_diff('second', Timestamp, FileTimestamp)) <= 600
// --- Exclude Microsoft system paths ---
| where not(FolderPath has_any (SystemPaths))
| extend RiskScore = case(
    FileCategory == "🔑 Credential/Secret", 10,
    8
)
| extend Severity = "🔴 Critical"
// --- Deduplicate ---
| summarize
    FirstSeen        = min(Timestamp),
    LastSeen         = max(Timestamp),
    ConnectionCount  = count(),
    RemotePorts      = make_set(RemotePort, 10),
    Processes        = make_set(InitiatingProcessFileName, 5)
    by DeviceName, RemoteIP, FileName, FolderPath, FileCategory, FileSHA256, Severity, RiskScore
| project
    FirstSeen,
    LastSeen,
    ConnectionCount,
    Severity,
    RiskScore,
    FileCategory,
    DeviceName,
    RemoteIP,
    RemotePorts,
    Processes,
    FileName,
    FolderPath,
    FileSHA256
| extend timestamp = FirstSeen, HostCustomEntity = DeviceName, IPCustomEntity = RemoteIP
| sort by RiskScore desc, LastSeen desc
```

---

## 📚 Reference

MITRE ATT&CK: T1041 (Exfiltration Over C2 Channel), T1005 (Data from Local System), T1552.001 (Unsecured Credentials: Credentials In Files), T1602 (Data from Configuration Repository).
