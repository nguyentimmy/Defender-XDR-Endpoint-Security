# 🧅 HTTP Executable Downloads + Tor Traffic

**Detects executable and script downloads over cleartext HTTP, then flags any that touch Tor infrastructure.**

---

## 🎯 Purpose

Encrypted traffic hides payload names, but plenty of malware still pulls its second stage over plain HTTP — and when it does, Defender's network signature inspection captures the raw request. That means the actual filename being downloaded is visible.

This hunt parses those inspected HTTP GET requests, keeps only the ones fetching executable or script content, and correlates the destination against Tor exit nodes, Tor ports, and Tor client processes.

A payload arriving over HTTP is worth a look. A payload arriving over HTTP **from a Tor exit node** is an attacker deliberately anonymizing their delivery infrastructure.

---

## 🔍 How it works

| Step | Logic |
| --- | --- |
| 1️⃣ | Filter `DeviceNetworkEvents` to `NetworkSignatureInspected` with signature `HTTP_Client` |
| 2️⃣ | Parse the request method from the matched content — keep `GET` only |
| 3️⃣ | Extract the requested filename and its extension |
| 4️⃣ | Keep only executable / script / container extensions (24 types) |
| 5️⃣ | Exclude known-good update and CDN destinations |
| 6️⃣ | Correlate against Tor exit nodes, ports, and processes |
| 7️⃣ | Score, dedupe, and rank |

---

## 🧅 Tor correlation

Three independent signals, weighted by how strongly each implies intent:

| Signal | Weight | Meaning |
| --- | --- | --- |
| **Exit node** | +4 | Download came **from** a live Tor exit node — strongest indicator |
| **Tor port** | +3 | Connection on 9001/9030/9040/9050/9051/9150/9151 |
| **Tor process** | +2 | `tor.exe`, `obfs4proxy.exe`, `meek-client.exe`, `snowflake-client.exe` |

The exit-node list is pulled live from the Tor Project's official bulk list.

---

## ⚖️ Additional risk signals

- 🔴 **High-risk extension** — `.exe`, `.dll`, `.scr`, `.ps1`, `.hta`, `.js`, `.vbs`, `.lnk`, `.iso`
- 🌐 **Raw-IP download** — no hostname, just an IP; skips DNS entirely
- 📡 **External destination** — public IP space

---

## 🔍 KQL

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

---

## 📚 Reference

MITRE ATT&CK: T1105 (Ingress Tool Transfer), T1071.001 (Application Layer Protocol: Web Protocols), T1090.003 (Proxy: Multi-hop Proxy / Tor).

Feed: `https://check.torproject.org/torbulkexitlist` — fetched live via `externaldata` on each run. For production, consider caching to a Sentinel Watchlist to avoid a dependency on external availability.
