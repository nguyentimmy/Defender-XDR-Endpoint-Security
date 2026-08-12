
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
// Correlates downloads of credential files AND FortiGate/Fortinet
// device configs with connections to known malicious IPs (Sentinel TI
// + abuse.ch Feodo C2, SSLBL, Blocklist.de) within a 10-minute window.
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
        // --- FortiGate / Fortinet device config formats ---
        or FileName endswith ".fgt"        // FortiGate config backup
        or FileName endswith ".fbf"        // Fortinet backup file
        or FileName endswith ".conf.gz"    // FortiGate compressed backup
        // --- Fortinet filename keyword matches ---
        or FileName has_any (
            "fortigate", "fortinet", "fgt_",
            "forti_backup", "fortigate-config",
            "sys_config"
        )
        | where FileName !in~ (
        ".ADOBE_WEBVIEW_FLAGS_SERVER.CONFIG",
        "ACSLEng.cfg",
        "LogTransport2.cfg",
        "STDeploy.exe.config"
    )
    | extend FileCategory = case(
        FileName has_any ("fortigate", "fortinet", "fgt_", "forti_backup",
                          "fortigate-config", "sys_config")
            or FileName endswith ".fgt" or FileName endswith ".fbf"
            or FileName endswith ".conf.gz", "🔥 FortiGate Config",
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
    FileCategory == "🔥 FortiGate Config", 10,
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