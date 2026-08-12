```
// ============================================================
// IIS LOG - Web Shell / Command Injection Detection
// ============================================================
// Hunts IIS logs for command-execution patterns (whoami, net user,
// cmd /c) appearing in URI queries, stems, or referers — a strong
// indicator of web shell activity or command injection attempts.
// ============================================================
let LookbackTime = 14d;
// --- Command execution patterns (non-capturing groups) ---
let CmdPatterns = "(?i)(?:net(?:1)?(?:\\.exe)?(?:%20|\\s|\\+){1,}(?:user|group|localgroup|view|share))|(?:cmd(?:\\.exe)?(?:%20|\\s|\\+){1,}/c)|(?:powershell(?:\\.exe)?)|(?:whoami)|(?:ipconfig)|(?:systeminfo)|(?:tasklist)|(?:certutil)|(?:bitsadmin)|(?:nltest)|(?:wmic)|(?:reg(?:\\.exe)?(?:%20|\\s|\\+){1,}query)";
W3CIISLog
| where TimeGenerated > ago(LookbackTime)
| where csUriQuery matches regex CmdPatterns
    or csUriStem matches regex CmdPatterns
    or csReferer matches regex CmdPatterns
| extend
    MatchedField = case(
        csUriQuery matches regex CmdPatterns, "csUriQuery",
        csUriStem matches regex CmdPatterns,  "csUriStem",
        csReferer matches regex CmdPatterns,  "csReferer",
        "Unknown"
    ),
    IsWebShellExt = (csUriStem has_any (".aspx", ".asp", ".ashx", ".asmx", ".php", ".jsp")),
    IsKnownWebShell = (csUriStem has_any (
        "cmd.aspx", "shell.aspx", "webshell", "antsword",
        "c99", "r57", "b374k", "wso",
        "eval", "tunnel.aspx"
    )),
    IsEncoded = (csUriQuery has_any ("%20", "%2f", "%5c", "base64", "FromBase64", "-enc", "-ec"))
| extend RiskScore = 2
                   + (toint(IsWebShellExt) * 2)
                   + (toint(IsKnownWebShell) * 4)
                   + (toint(IsEncoded) * 2)
| extend Severity = case(
    RiskScore >= 6, "🔴 Critical",
    RiskScore >= 4, "🟠 High",
    "🟡 Medium"
)
| summarize
    StartTime       = min(TimeGenerated),
    EndTime         = max(TimeGenerated),
    ConnectionCount = count(),
    DistinctUris    = dcount(csUriStem),
    SampleQueries   = make_set(csUriQuery, 10),
    StatusCodes     = make_set(scStatus, 10)
    by Computer, sSiteName, sIP, cIP, csUserName,
       csMethod, MatchedField,
       IsWebShellExt, IsKnownWebShell, IsEncoded,
       Severity, RiskScore
| project
    StartTime,
    EndTime,
    Severity,
    RiskScore,
    ConnectionCount,
    DistinctUris,
    Computer,
    sSiteName,
    sIP,
    cIP,
    csUserName,
    csMethod,
    MatchedField,
    IsWebShellExt,
    IsKnownWebShell,
    IsEncoded,
    StatusCodes,
    SampleQueries
| extend
    timestamp           = StartTime,
    IPCustomEntity      = cIP,
    HostCustomEntity    = Computer,
    AccountCustomEntity = csUserName
| sort by RiskScore desc, ConnectionCount desc
```