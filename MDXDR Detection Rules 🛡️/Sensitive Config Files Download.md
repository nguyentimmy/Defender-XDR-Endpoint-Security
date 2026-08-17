# 🚨 Sensitive Credential File Exfil to Malicious IP

**Detection rule — fires when a credential or secret file is created on a host within 5 minutes of that host contacting known-malicious infrastructure.**

---

## 🎯 Purpose

Credential files landing on disk happen constantly across a fleet. Connections to malicious IPs happen daily on most networks. Neither alone is worth waking someone up. **Both on the same host inside a 5-minute window** — that's the specific pattern this rule fires on, and it's precise enough to auto-respond to.

This is the promoted subset of the broader `Sensitive Config Exfil` hunt. The hunt covers general configs (`.conf`, `.cfg`, `.ini`) with a wider 10-minute window and live TI feed fetches — good for weekly workbook review, too noisy for scheduled alerting. This rule strips down to credential extensions only, tightens the correlation window to 5 minutes, and uses a Watchlist-backed feed to avoid external HTTP fetches at rule runtime.

---

## 🔍 How it works

| Step | Logic |
| --- | --- |
| 1️⃣ | Build `MaliciousIPs` from Sentinel TI (active + non-expired) unioned with the `MaliciousIPs` Watchlist (populated from abuse.ch feeds via scheduled Logic App) |
| 2️⃣ | Materialize `SensitiveFiles` — credential file creates in the window, outside Microsoft system paths |
| 3️⃣ | Query `DeviceNetworkEvents` for public-IP connections from browsers, PowerShell, cmd, or transfer LOLBins to any IP in `MaliciousIPs` |
| 4️⃣ | Inner join on `DeviceId` — must be the same host |
| 5️⃣ | Require the two events within **300 seconds** of each other |
| 6️⃣ | Summarize per Device + IP + File, capture whether the file appeared before the connection |
| 7️⃣ | Map entities (Host, IP, Account, FileHash) for auto-enrichment and response actions |

---

## ⚙️ Rule configuration

| Setting | Value |
| --- | --- |
| **Frequency** | 1 hour |
| **Lookback period** | 1 hour |
| **Severity** | High |
| **Event grouping** | Group all events per Device + IP into a single incident |
| **Correlation window** | 300 seconds — tightened from 600 in the hunt version |
| **Ingestion delay buffer** | 10 minutes added to lookback |
| **Entities mapped** | Host, IP, Account, FileHash |

**Watchlist dependency:** the rule expects a Sentinel Watchlist named `MaliciousIPs` with an `IPAddress` column, populated on a schedule from Feodo Tracker, SSLBL, and Blocklist.de via a Logic App. This avoids an external HTTP fetch on every rule execution — important for reliability at short cadences.

**Credential file scope** (intentionally narrower than the hunt):

| Category | Extensions |
| --- | --- |
| SSH / TLS keys | `.pem`, `.key`, `.ppk` |
| Certificate stores | `.pfx`, `.p12`, `.jks`, `.keystore` |
| Environment secrets | `.env` |
| Password databases | `.kdbx` |
| Remote access configs | `.ovpn`, `.rdp` |

General config extensions (`.conf`, `.cfg`, `.ini`, `.config`) are **not** included — they generate too many false positives from legitimate application activity. Those stay in the workbook hunt for periodic review.

**Response guidance when the rule fires:** treat as active credential exfiltration in progress. Isolate the device, revoke and rotate anything the file could contain, capture the file for analysis before any cleanup, and pivot on the `RemoteIP` across other hosts to check for a broader compromise.

---

## 🔍 KQL

```kql
// ============================================================
// [DETECTION RULE] Sensitive Credential File Exfil to Malicious IP
// ============================================================
// MITRE ATT&CK:
//   Tactic:    Exfiltration, Collection, Credential Access
//   Technique: T1041     - Exfiltration Over C2 Channel
//              T1005     - Data from Local System
//              T1552.001 - Unsecured Credentials: Credentials In Files
// ============================================================
// RULE CONFIG: Frequency 1h | Lookup period 1h | Severity High
//              Group all events into a single incident per Device+IP
// ------------------------------------------------------------
// Fires when a credential/secret file is created on a host within 5
// minutes of that host contacting known-malicious infrastructure.
// Tuned for alerting: credential file types only, tight correlation
// window, Watchlist-backed feeds (no live fetch at rule runtime).
// ============================================================
let LookbackTime = 1h;
let IngestionDelay = 10m;
let CorrelationWindow = 300;      // seconds - tightened from hunt version
// --- Feed 1: native Sentinel TI (always available) ---
let TI_IPs = ThreatIntelligenceIndicator
    | where TimeGenerated > ago(30d)
    | where Active == true
    | where isnotempty(NetworkIP)
    | summarize arg_max(TimeGenerated, *) by NetworkIP
    | where ExpirationDateTime > now()
    | distinct MalIP = NetworkIP;
// --- Feed 2: abuse.ch feeds via Watchlist ---
// Populate a Watchlist named 'MaliciousIPs' with a column 'IPAddress'
// from Feodo/SSLBL/Blocklist.de on a scheduled Logic App. Avoids an
// external HTTP fetch on every rule execution.
let Watchlist_IPs = materialize(
    _GetWatchlist('MaliciousIPs')
    | project MalIP = tostring(IPAddress)
    | where MalIP matches regex @"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    | distinct MalIP
);
let MaliciousIPs = materialize(
    union isfuzzy=true (TI_IPs), (Watchlist_IPs)
    | distinct MalIP
);
// --- Credential/secret file types ONLY - general configs removed ---
let CredentialExtensions = dynamic([
    ".env", ".pem", ".key", ".pfx", ".p12",
    ".kdbx", ".ppk", ".ovpn", ".rdp", ".jks", ".keystore"
]);
let SystemPaths = dynamic([
    "\\ProgramData\\Microsoft\\",
    "\\Windows\\AppRepository\\",
    "\\Microsoft\\Diagnosis\\",
    "\\Windows\\System32\\config\\",
    "\\Program Files\\WindowsApps\\",
    "\\Windows\\WinSxS\\",
    "\\Windows\\servicing\\"
]);
// --- Sensitive file activity in the window ---
// DeviceName intentionally dropped here to avoid a join-side collision;
// we take DeviceName from the network-events side after the join.
let SensitiveFiles = materialize(
    DeviceFileEvents
    | where TimeGenerated > ago(LookbackTime + IngestionDelay)
    | where ActionType in ("FileCreated", "FileDownloaded", "FileModified")
    | where FileName has_any (CredentialExtensions)
    | where not(FolderPath has_any (SystemPaths))
    | extend FileExt = tolower(extract(@"(\.[^.\\/]+)$", 1, FileName))
    | where FileExt in~ (CredentialExtensions)
    | project
        FileTime = TimeGenerated,
        DeviceId,
        FileName,
        FolderPath,
        FileSHA256 = SHA256,
        FileAccount = InitiatingProcessAccountName,
        FileProcess = InitiatingProcessFileName
);
// --- Malicious-IP contact in the window ---
DeviceNetworkEvents
| where TimeGenerated > ago(LookbackTime + IngestionDelay)
| where RemoteIPType == "Public"
| where InitiatingProcessFileName in~ (
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe",
    "tor.exe", "torbrowser.exe",
    "powershell.exe", "pwsh.exe", "cmd.exe",
    "curl.exe", "wget.exe", "certutil.exe", "bitsadmin.exe",
    "rclone.exe", "winscp.exe", "ftp.exe"
)
| where RemoteIP in (MaliciousIPs)
| project
    NetTime = TimeGenerated,
    DeviceId,
    DeviceName,
    RemoteIP,
    RemotePort,
    RemoteUrl,
    NetProcess = InitiatingProcessFileName,
    NetProcessCmd = InitiatingProcessCommandLine,
    NetAccount = InitiatingProcessAccountName
| join kind=inner (SensitiveFiles) on DeviceId
// --- Temporal correlation is the detection ---
| where abs(datetime_diff('second', NetTime, FileTime)) <= CorrelationWindow
| extend
    SecondsApart = abs(datetime_diff('second', NetTime, FileTime)),
    FileFirst = FileTime < NetTime
// --- One row per device + IP + file ---
| summarize
    FirstSeen       = min(min_of(NetTime, FileTime)),
    LastSeen        = max(max_of(NetTime, FileTime)),
    ConnectionCount = count(),
    ClosestGapSec   = min(SecondsApart),
    RemotePorts     = make_set(RemotePort, 5),
    NetProcesses    = make_set(NetProcess, 5),
    FileProcesses   = make_set(FileProcess, 5),
    SampleCmd       = take_any(substring(NetProcessCmd, 0, 250)),
    FileBeforeConn  = max(FileFirst)
    by DeviceId, DeviceName, RemoteIP, FileName, FolderPath,
       FileSHA256, Account = FileAccount
| extend
    Severity  = "High",
    AlertName = strcat("Credential file activity correlated with malicious IP contact on ", DeviceName)
// --- Entity mapping for Sentinel incident enrichment ---
| extend
    timestamp            = FirstSeen,
    HostCustomEntity     = DeviceName,
    IPCustomEntity       = RemoteIP,
    AccountCustomEntity  = Account,
    FileHashCustomEntity = FileSHA256
| project
    FirstSeen,
    LastSeen,
    Severity,
    AlertName,
    DeviceName,
    Account,
    RemoteIP,
    RemotePorts,
    ClosestGapSec,
    FileBeforeConn,
    ConnectionCount,
    NetProcesses,
    FileProcesses,
    FileName,
    FolderPath,
    FileSHA256,
    SampleCmd,
    HostCustomEntity,
    IPCustomEntity,
    AccountCustomEntity,
    FileHashCustomEntity,
    timestamp
| sort by ClosestGapSec asc, FirstSeen desc
```

---

## 📚 Reference

MITRE ATT&CK: T1041 (Exfiltration Over C2 Channel), T1005 (Data from Local System), T1552.001 (Unsecured Credentials: Credentials In Files), T1602 (Data from Configuration Repository).