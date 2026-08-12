```
// ============================================================
// HTTP EXECUTABLE DOWNLOADS + TOR TRAFFIC (Cleartext Inspection)
// ============================================================
// MITRE ATT&CK:
//   Tactic:    Command and Control, Execution, Defense Evasion
//   Technique: T1105 - Ingress Tool Transfer
//              T1071.001 - Application Layer Protocol: Web Protocols
//              T1090.003 - Proxy: Multi-hop Proxy (Tor)
// ============================================================
// Inspects cleartext HTTP GET traffic for executable/script downloads,
// and flags any that involve Tor infrastructure (exit nodes, Tor ports,
// or Tor processes) — surfacing anonymized tool transfer & C2.
// ============================================================
let LookbackTime = 14d;
let ExecutableFileExtensions = dynamic([
    "bat", "cmd", "com", "cpl", "dll", "ex", "exe",
    "hta", "jar", "js", "jse", "lnk", "msc", "msi",
    "ps1", "py", "reg", "scr", "vb", "vbe", "vbs",
    "ws", "wsf", "iso", "img"
]);
// === Tor exit node list (official Tor Project) ===
let TorExitNodes = materialize(
    externaldata(Indicator:string)
    [@"https://check.torproject.org/torbulkexitlist"]
    with (format="txt")
    | where Indicator matches regex @"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    | distinct Indicator
);
let TorPorts = dynamic([9001, 9030, 9040, 9050, 9051, 9150, 9151]);
let TorProcesses = dynamic([
    "tor.exe", "torbrowser.exe", "firefox.exe",   // Tor Browser uses Firefox ESR
    "obfs4proxy.exe", "meek-client.exe", "snowflake-client.exe"
]);
DeviceNetworkEvents
| where TimeGenerated > ago(LookbackTime)
| where ActionType == "NetworkSignatureInspected"
| extend
    SignatureName           = tostring(parse_json(AdditionalFields).SignatureName),
    SignatureMatchedContent = tostring(parse_json(AdditionalFields).SignatureMatchedContent),
    SamplePacketContent     = tostring(parse_json(AdditionalFields).SamplePacketContent)
| where SignatureName == "HTTP_Client"
// --- Parse request method & downloaded file ---
| extend HTTP_Request_Method = tostring(split(SignatureMatchedContent, " /", 0)[0])
| where HTTP_Request_Method == "GET"
| extend DownloadedContent = extract(@'.*/(.*)HTTP', 1, SignatureMatchedContent)
| extend DownloadFileExtension = tolower(extract(@'.*\.(.*)$', 1, DownloadedContent))
// --- Executable/script downloads only ---
| where isnotempty(DownloadFileExtension)
    and string_size(DownloadFileExtension) < 8
    and DownloadFileExtension has_any (ExecutableFileExtensions)
// --- Exclude known-good update/CDN destinations ---
| where not(SignatureMatchedContent has_any (
    "microsoft.com", "windowsupdate.com", "msftncsi.com",
    "azureedge.net", "akamai", "windows.com",
    "digicert.com", "symantec.com"
))
// --- Tor correlation ---
| extend
    IsTorExitNode  = RemoteIP in (TorExitNodes),
    IsTorPort      = RemotePort in (TorPorts),
    IsTorProcess   = InitiatingProcessFileName in~ (TorProcesses)
| extend IsTorRelated = IsTorExitNode or IsTorPort or IsTorProcess
// --- Enrich / flag indicators ---
| extend
    IsRawIPDownload   = isnotempty(RemoteIP) and RemoteUrl == "",
    IsHighRiskExt     = DownloadFileExtension in~ ("exe", "dll", "scr", "ps1", "hta", "js", "vbs", "lnk", "iso"),
    IsRemoteExternal  = RemoteIPType == "Public"
// --- Risk Score (Tor weighted heavily) ---
| extend RiskScore = 2
                   + (toint(IsHighRiskExt) * 2)
                   + (toint(IsRawIPDownload) * 2)
                   + (toint(IsRemoteExternal) * 1)
                   + (toint(IsTorExitNode) * 4)     // download FROM a Tor exit node
                   + (toint(IsTorPort) * 3)
                   + (toint(IsTorProcess) * 2)
| extend Severity = case(
    RiskScore >= 7, "🔴 Critical",
    RiskScore >= 4, "🟠 High",
    "🟡 Medium"
)
// --- Deduplicate ---
| summarize
    FirstSeen      = min(TimeGenerated),
    LastSeen       = max(TimeGenerated),
    DownloadCount  = count(),
    RemoteIPs      = make_set(RemoteIP, 20),
    Files          = make_set(DownloadedContent, 20)
    by DeviceName, InitiatingProcessFileName,
       DownloadFileExtension, Severity, RiskScore,
       IsHighRiskExt, IsRawIPDownload,
       IsTorRelated, IsTorExitNode, IsTorPort, IsTorProcess
| project
    FirstSeen,
    LastSeen,
    Severity,
    RiskScore,
    DownloadCount,
    DeviceName,
    InitiatingProcessFileName,
    DownloadFileExtension,
    IsTorRelated,
    IsTorExitNode,
    IsTorPort,
    IsTorProcess,
    Files,
    RemoteIPs,
    IsHighRiskExt,
    IsRawIPDownload
// --- Entity mapping ---
| extend
    timestamp        = FirstSeen,
    HostCustomEntity = DeviceName
| sort by RiskScore desc, DownloadCount desc
```