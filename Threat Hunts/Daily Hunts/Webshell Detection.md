# 🐚 IIS Web Shell & Command Injection Detection

**Hunts IIS logs for command-execution patterns appearing in URI queries, stems, and referers — the fingerprint of web shell activity.**

---

## 🎯 Purpose

A web shell turns a public-facing IIS server into a remote console. The commands an attacker runs through it — `whoami`, `net user`, `cmd /c` — end up embedded in the HTTP request itself, which means IIS logs them.

This hunt inspects three fields where those commands surface, then scores each hit on whether the target looks like a shell, whether the payload is obfuscated, and whether the filename matches a known web shell family.

Web shells are also a persistence mechanism that survives endpoint remediation entirely. Reimaging a workstation does nothing if the shell is still sitting on a web server.

---

## 🔍 Where it looks

| Field | Why it matters |
| --- | --- |
| **`csUriQuery`** | The query string — where commands are usually passed |
| **`csUriStem`** | The requested path — reveals the shell file itself |
| **`csReferer`** | Sometimes carries injected content or chained requests |

`MatchedField` is carried into the output so you know which one fired.

---

## 🧬 Command patterns detected

`net user` / `net group` / `net localgroup` / `net view` / `net share`, `cmd /c`, `powershell`, `whoami`, `ipconfig`, `systeminfo`, `tasklist`, `certutil`, `bitsadmin`, `nltest`, `wmic`, `reg query`

The regex accounts for URL encoding and separator variants — `%20`, `+`, and literal whitespace all match, since attackers encode the space between a binary and its arguments.

Built with **non-capturing groups** (`(?:...)`) throughout. KQL's `matches regex` fails past 16 capturing groups, so this is a functional requirement, not a style choice.

---

## ⚖️ Risk signals

| Signal | Weight | Meaning |
| --- | --- | --- |
| **Base — command pattern in request** | 2 | Something command-shaped hit the server |
| 🎯 **Known web shell name** | +4 | `cmd.aspx`, `shell.aspx`, `antsword`, `c99`, `r57`, `b374k`, `wso`, `eval` |
| 📄 **Web shell extension** | +2 | `.aspx`, `.asp`, `.ashx`, `.asmx`, `.php`, `.jsp` |
| 🔐 **Encoded payload** | +2 | `%20`, `%2f`, `%5c`, `base64`, `FromBase64`, `-enc` |

A known shell filename is the strongest single indicator — those names come from public shell kits and have no legitimate reason to appear in a request path.

---

## 📤 Output

Per server, site, source IP, and matched field: request count, distinct URIs touched, HTTP method, sample query strings, and the returned status codes.

**`StatusCodes` is the triage column.** A `200` on a command-injection request means the server processed it and returned content — the shell is working. Consistent `404` or `403` responses suggest scanning or a shell that has already been removed.


```
// ============================================================
// IIS LOG - Web Shell / Command Injection Detection
// ============================================================
// MITRE ATT&CK:
//   Tactic:    Persistence, Initial Access, Execution
//   Technique: T1505.003 - Server Software Component: Web Shell
//              T1190     - Exploit Public-Facing Application
//              T1059.003 - Command and Scripting Interpreter: Windows Command Shell
//              T1027     - Obfuscated Files or Information (encoded payloads)
// ============================================================
// Hunts IIS logs for command-execution patterns (whoami, net user,
// cmd /c) appearing in URI queries, stems, or referers — a strong
// indicator of web shell activity or command injection attempts.
// NOTE: regex uses non-capturing groups (?:...) throughout — KQL's
// 'matches regex' fails beyond 16 capturing groups.
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

---

## 📚 Reference

MITRE ATT&CK: T1505.003 (Server Software Component: Web Shell), T1190 (Exploit Public-Facing Application), T1059.003 (Windows Command Shell).

Requires IIS logs ingested into `W3CIISLog` via the Log Analytics agent or AMA.
