
```
// ============================================================
// Highly Suspicious Execution on Powershell
// ============================================================
// MITRE ATT&CK:
//   Tactic:    Command and Control, Execution, Defense Evasion
//   Technique: T1059.001 - Command and Scripting Interpreter: PowerShell
//              T1105      - Ingress Tool Transfer
//              T1027      - Obfuscated Files or Information
// ============================================================
// Hunts for PowerShell downloading from non-trusted URLs, scores each
// command against download/obfuscation/bypass/execution indicators, and
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
// --- Exclude known-good domains ---
| where not(ProcessCommandLine has_any (
    "microsoft.com", "windowsupdate.com", "office.com",
    "live.com", "azure.com", "azureedge.net",
    "github.com", "githubusercontent.com",
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
// --- High-risk indicators ---
| extend
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
    // --- NEW: parent process is a major phishing signal ---
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
       IsMaliciousFileType, IsSuspiciousPath, IsEncoded,
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