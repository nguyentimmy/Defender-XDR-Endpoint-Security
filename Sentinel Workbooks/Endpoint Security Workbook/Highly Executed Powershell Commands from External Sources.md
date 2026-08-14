# 🎯 Highly Suspicious PowerShell Execution

**Hunts PowerShell downloading from untrusted external sources, scoring each command against source, obfuscation, bypass, and execution indicators.**

---

## 🎯 Purpose

PowerShell is the most abused execution vector on Windows. Legitimate admin scripts and malicious download cradles use the same cmdlets, which makes noisy alerting on `Invoke-WebRequest` or `DownloadString` a non-starter. The distinction lives in *combinations* — an encoded, hidden-window PowerShell spawned by Word, pulling an `.exe` from an untrusted external host is a different animal than an admin running `Invoke-WebRequest` against a Microsoft update URL.

Rather than chase an endless blocklist of bad hosting sites, this hunt flips the logic: it hard-excludes pure noise (Microsoft, package repos, connectivity checks), recognizes a broad set of legitimate CDNs and dev ecosystems, and flags **any other external source** — file-sharing sites, chat CDNs, paste dumps, AI tool domains, tunnels, and unknown hosts alike. Everything is then scored against seven weighted signals, with parent process weighted highest since Office spawning PowerShell is the classic phishing chain.

---

## 🔍 How it works

| Step | Logic |
| --- | --- |
| 1️⃣ | Filter `DeviceProcessEvents` to `powershell.exe`, `pwsh.exe`, or `powershell_ise.exe` in the last 14 days |
| 2️⃣ | Keep only commands using web download methods (`Invoke-WebRequest`, `DownloadString`, `Start-BitsTransfer`, etc.) referencing `http://`, `https://`, or `ftp://` |
| 3️⃣ | Hard-exclude pure noise — Microsoft, Windows Update, package repos — and connectivity-check patterns |
| 4️⃣ | Extract the URL and domain for pivot |
| 5️⃣ | Recognize a broad scoring allowlist of legit CDNs and dev ecosystems; flag any domain outside it as an external source |
| 6️⃣ | Tag the remaining risk indicators against command line and parent process |
| 7️⃣ | Score with weighted multipliers, filter to `RiskScore >= 2`, label severity |
| 8️⃣ | Dedupe by device/account/command — surface first/last seen and occurrence count |

---

## ⚖️ Scoring model

Each command is scored against weighted signals. Weights reflect how strongly each implies malicious intent — parent process carries the most because Office spawning PowerShell is the classic phishing chain.

| Signal | Weight | Meaning |
| --- | --- | --- |
| **Office parent** | ×4 | `winword.exe`, `excel.exe`, `outlook.exe` etc. spawned the PowerShell — macro or exploit execution |
| **External source** | ×3 | Download host isn't Microsoft/package-repo (hard-excluded) or a known-good CDN — captures file-share, chat CDN, paste, AI, tunnel, and unknown domains |
| **Raw IP / suspicious TLD** | ×3 | Bare IP (skips DNS) or abused TLD (`.tk`, `.ru`, `.top`, `.xyz`, `.zip`, `.mov`) |
| **Encoded** | ×2 | Base64 (`-enc`, `FromBase64String`), `[char]` arrays, or `-join` reassembly — obfuscation |
| **Bypass attempt** | ×2 | `-ExecutionPolicy Bypass`, `-NoProfile`, `-WindowStyle Hidden`, `-NonInteractive` |
| **Chained execution** | ×2 | `Invoke-Expression`, `iex`, `\| iex`, `Start-Process` — payload runs immediately |
| **Script host parent** | ×2 | `wscript.exe`, `cscript.exe`, `mshta.exe`, `cmd.exe` launched the PowerShell |
| **Malicious file type** | ×1 | Download target is an executable, script, or archive |
| **Suspicious path** | ×1 | Payload lands in `Temp`, `AppData`, `Downloads`, `Public`, or `ProgramData` |

**Severity thresholds:**

| Score | Severity |
| --- | --- |
| 7+ | 🔴 Critical |
| 4–6 | 🟠 High |
| 2–3 | 🟡 Medium |

A high `OccurrenceCount` on the same command across devices or sessions raises priority further — it suggests a campaign or established persistence rather than a one-off.

**Two-tier trust design:** hard exclusions (top of query) remove domains so common and safe they aren't worth looking at — they never reach scoring. The scoring allowlist recognizes legitimate CDNs and package ecosystems that shouldn't inflate the score but are still worth seeing if they stack with other bad signals. Everything outside both lists is treated as an untrusted external source. Tune both lists to your environment.

---

## 🔍 KQL

```kql
// ============================================================
// Highly Suspicious Execution on Powershell
// ============================================================
// MITRE ATT&CK:
//   Tactic:    Command and Control, Execution, Defense Evasion
//   Technique: T1059.001 - Command and Scripting Interpreter: PowerShell
//              T1105      - Ingress Tool Transfer
//              T1027      - Obfuscated Files or Information
// ============================================================
// Hunts for PowerShell downloading from untrusted external sources, scores
// each command against source/obfuscation/bypass/execution indicators, and
// surfaces the extracted URL, domain, and launching parent process.
// ============================================================
let LookbackTime = 14d;
DeviceProcessEvents
| where TimeGenerated > ago(LookbackTime)
| where FileName in~ ("powershell.exe", "pwsh.exe", "powershell_ise.exe")
// --- Web download methods ---
| where ProcessCommandLine has_any (
    "Invoke-WebRequest", "iwr", "wget", "curl",
    "DownloadFile", "DownloadString", "DownloadData",
    "Net.WebClient", "Net.Http", "HttpClient",
    "Start-BitsTransfer", "Invoke-RestMethod", "irm"
)
| where ProcessCommandLine has_any ("http://", "https://", "ftp://")
// --- HARD EXCLUSIONS: pure noise, removed entirely ---
| where not(ProcessCommandLine has_any (
    "microsoft.com", "windowsupdate.com", "office.com",
    "live.com", "azure.com", "azureedge.net",
    "nuget.org", "powershellgallery.com",
    "visualstudio.com", "msftconnecttest.com"
))
// --- Exclude connectivity checks ---
| where not(ProcessCommandLine has_any (
    "google.com", "gstatic.com", "connectivitycheck"
) and ProcessCommandLine has_any (
    "OpenRead", "CanRead", "GetResponse", "CheckConnectivity"
))
// --- Extract the URL & domain from the command ---
| extend ExtractedUrl = extract(@"(https?://[^\s'""\)]+)", 1, ProcessCommandLine)
| extend ExtractedDomain = tolower(extract(@"https?://([^/:\s'""\)]+)", 1, ProcessCommandLine))
// --- SCORING ALLOWLIST: legitimate but still visible if stacked ---
| extend IsKnownTrustedDomain = ExtractedDomain has_any (
    // CDNs & infrastructure commonly seen in legit scripts
    "akamai", "cloudfront.net", "fastly", "jsdelivr.net", "cdnjs",
    "amazonaws.com", "core.windows.net", "digicert.com",
    "letsencrypt.org", "sectigo.com", "verisign",
    // Package / dev ecosystems
    "python.org", "pypi.org", "pythonhosted.org",
    "nodejs.org", "npmjs.org", "chocolatey.org",
    "docker.io", "docker.com", "jenkins.io",
    "github.com", "githubusercontent.com",
    // Common vendor domains (tune to environment)
    "adobe.com", "mozilla.org", "ubuntu.com", "debian.org", "redhat.com"
)
// --- High-risk indicators ---
| extend
    IsExternalSource = iff(
        isnotempty(ExtractedDomain) and not(IsKnownTrustedDomain), "YES", ""),
    IsMaliciousFileType = ProcessCommandLine has_any (
        ".exe", ".ps1", ".bat", ".vbs", ".dll",
        ".msi", ".hta", ".js", ".lnk", ".zip", ".rar", ".scr"
    ),
    IsSuspiciousPath = ProcessCommandLine has_any (
        "\\temp\\", "\\tmp\\", "\\appdata\\",
        "\\public\\", "\\downloads\\", "\\programdata\\",
        "%temp%", "%appdata%", "%public%"
    ),
    IsEncoded = ProcessCommandLine has_any (
        "-enc", "-ec", "EncodedCommand",
        "FromBase64String", "ToBase64String",
        "[char]", "-join", "-replace"
    ),
    IsBypassAttempt = ProcessCommandLine has_any (
        "bypass", "unrestricted", "hidden",
        "noprofile", "noninteractive", "-nop", "-w hidden"
    ),
    IsChainedExecution = ProcessCommandLine has_any (
        "iex", "Invoke-Expression",
        "Start-Process", "& (", "| iex",
        ".Run(", "Shellexecute"
    ),
    IsRawIPorSuspiciousTLD = ProcessCommandLine matches regex
        @"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\.tk|\.ru|\.cn|\.top|\.xyz|\.pw|\.cc|\.zip|\.mov",
    // --- parent process is a major phishing signal ---
    IsOfficeParent = InitiatingProcessFileName in~ (
        "winword.exe", "excel.exe", "powerpnt.exe",
        "outlook.exe", "onenote.exe", "mspub.exe", "msaccess.exe"
    ),
    IsScriptHostParent = InitiatingProcessFileName in~ (
        "wscript.exe", "cscript.exe", "mshta.exe", "cmd.exe"
    )
// --- Risk Score ---
| extend RiskScore = toint(IsMaliciousFileType)
                   + toint(IsSuspiciousPath)
                   + (iff(IsExternalSource == "YES", 1, 0) * 3)
                   + (toint(IsEncoded) * 2)
                   + (toint(IsBypassAttempt) * 2)
                   + (toint(IsChainedExecution) * 2)
                   + (toint(IsRawIPorSuspiciousTLD) * 3)
                   + (toint(IsOfficeParent) * 4)        // Office spawning PS = classic phishing
                   + (toint(IsScriptHostParent) * 2)
| where RiskScore >= 2
| extend Severity = case(
    RiskScore >= 7, "🔴 Critical",
    RiskScore >= 4, "🟠 High",
    "🟡 Medium"
)
// --- Deduplicate ---
| summarize
    FirstSeen       = min(TimeGenerated),
    LastSeen        = max(TimeGenerated),
    OccurrenceCount = count()
    by DeviceName, AccountName, ProcessCommandLine,
       ExtractedDomain, ExtractedUrl,
       InitiatingProcessFileName,
       IsExternalSource, IsMaliciousFileType, IsSuspiciousPath, IsEncoded,
       IsBypassAttempt, IsChainedExecution, IsRawIPorSuspiciousTLD,
       IsOfficeParent, IsScriptHostParent,
       Severity, RiskScore
| project
    FirstSeen,
    LastSeen,
    OccurrenceCount,
    Severity,
    RiskScore,
    DeviceName,
    AccountName,
    ParentProcess = InitiatingProcessFileName,
    ExtractedDomain,
    ExtractedUrl,
    ProcessCommandLine,
    IsExternalSource,
    IsOfficeParent,
    IsMaliciousFileType,
    IsSuspiciousPath,
    IsEncoded,
    IsBypassAttempt,
    IsChainedExecution,
    IsRawIPorSuspiciousTLD
// --- Entity mapping ---
| extend
    timestamp        = FirstSeen,
    HostCustomEntity = DeviceName,
    AccountCustomEntity = AccountName
| sort by RiskScore desc, OccurrenceCount desc
```

---

## 📚 Reference

MITRE ATT&CK: T1059.001 (Command and Scripting Interpreter: PowerShell), T1105 (Ingress Tool Transfer), T1027 (Obfuscated Files or Information), T1027.010 (Command Obfuscation), T1140 (Deobfuscate/Decode Files or Information), T1204.002 (User Execution: Malicious File), T1218 (System Binary Proxy Execution), T1567 (Exfiltration Over Web Service).