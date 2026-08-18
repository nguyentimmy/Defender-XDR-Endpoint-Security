# 🎭 LOLBin Abuse — Living-off-the-Land Binary Execution

**Detects signed Microsoft binaries being abused to download, decode, or proxy-execute payloads — classified by technique and confidence.**

---

## 🎯 Purpose

A LOLBin is a legitimate signed OS binary — like `certutil` or `rundll32` — that attackers abuse instead of their own malware. Because it's trusted and admins use it too, it evades AV and application control and blends into normal activity. That's why you can't just block them — you have to detect how they're being used.

This hunt matches each execution against known abuse patterns (Squiblydoo, Follina, comsvcs LSASS dump, certutil URL cache, etc.), tags high-confidence techniques distinctly from suspicious-but-ambiguous ones, then layers supporting context — URL, UNC path, user-writable location, suspicious parent, elevation — to score. The `IsHighConfidence` flag carries through so the top tier can be promoted to a scheduled rule with confidence, while the lower tier stays in the workbook for review.

---

## 🔍 How it works

| Step | Logic |
| --- | --- |
| 1️⃣ | Filter `DeviceProcessEvents` to 21 known LOLBins in the last 7 days |
| 2️⃣ | Strip the binary's own `.exe` from the command line so `certutil.exe` doesn't self-match `.exe` in args |
| 3️⃣ | Classify by technique using a `case()` chain — 🔴 high-confidence abuse patterns, 🟠 suspicious-but-ambiguous |
| 4️⃣ | Drop unclassified rows (didn't match a known abuse pattern) |
| 5️⃣ | Exclude signed management tooling paths — SCCM (`CCM`), Intune, Monitoring Agent, Group Policy |
| 6️⃣ | Tag supporting context: URL present, UNC path, user-writable folder, suspicious parent, elevation |
| 7️⃣ | Score with base 4 plus weighted context; label severity |
| 8️⃣ | Dedupe by device/account/technique/parent — surface first/last seen and occurrence count |

---

## 🎭 Techniques detected

| LOLBin | Fires on |
| --- | --- |
| **certutil** | 🔴 URL cache download; 🔴 Base64 encode/decode |
| **regsvr32** | 🔴 Squiblydoo (`scrobj.dll`, remote scriptlet); 🔴 direct HTTP load |
| **mshta** | 🔴 Remote script or `javascript:`/`vbscript:` protocol |
| **rundll32** | 🔴 Script protocol; 🔴 `comsvcs` LSASS dump; 🔴 DLL from user-writable path; 🟠 URL/shell execution |
| **bitsadmin** | 🔴 Background transfer (`/transfer`, `/addfile`, `/create`) |
| **installutil / regasm / regsvcs** | 🔴 .NET assembly proxy execution |
| **msbuild** | 🟠 Project file execution outside management tooling |
| **wmic** | 🔴 Remote XSL execution (`/format:http`) |
| **cmstp** | 🔴 INF-driven execution |
| **odbcconf** | 🔴 DLL registration via response file |
| **msxsl** | 🟠 XSL transformation (unusual outside dev) |
| **forfiles / pcalua / xwizard** | 🟠 Proxied launch to break parent-child chain |
| **msdt** | 🔴 Follina-class diagnostic tool abuse |
| **diskshadow** | 🟠 Scripted mode (VSS abuse) |

---

## ⚖️ Scoring model

Base score of 4 for any matched technique, plus weighted context signals. Suspicious parent process carries the most weight because Office or script host launching a LOLBin is the classic phishing chain.

| Signal | Weight | Meaning |
| --- | --- | --- |
| **Base score** | 4 | Any technique classified (starting floor) |
| **Suspicious parent** | +4 | Parent is Office, script host, or browser |
| **High-confidence technique** | +3 | Technique classified 🔴 rather than 🟠 |
| **Has URL** | +2 | Command line references `http://`, `https://`, or `ftp://` |
| **From user-writable path** | +2 | LOLBin executing from `Temp`, `AppData`, `Downloads`, `Public`, or `ProgramData` |
| **Has UNC path** | +1 | Command line references a `\\` share path |
| **Elevated** | +1 | Running at High or System integrity |

**Severity thresholds:**

| Score | Severity |
| --- | --- |
| 11+ | 🔴 Critical |
| 8–10 | 🟠 High |
| 6–7 | 🟡 Medium |
| < 6 | 🟢 Low |

The `IsHighConfidence` column carries through the summarize step. Filter to `IsHighConfidence == true` when promoting to a scheduled analytics rule — the lower-confidence tier is better suited to workbook review than automated alerting.

---

## 🔍 KQL

```kql
// ============================================================
// LOLBIN ABUSE - Living-off-the-Land Binary Execution
// ============================================================
// MITRE ATT&CK:
//   Tactic:    Execution, Defense Evasion, Command and Control
//   Technique: T1218     - System Binary Proxy Execution
//              T1218.010 - Regsvr32 (Squiblydoo)
//              T1218.011 - Rundll32
//              T1218.005 - Mshta
//              T1105     - Ingress Tool Transfer
//              T1140     - Deobfuscate/Decode Files or Information
//              T1197     - BITS Jobs
// ============================================================
// Signed Microsoft binaries abused to download, decode, or proxy-execute
// payloads. Each row is classified by technique and confidence so the
// high-confidence subset can be promoted to a scheduled rule.
// ============================================================
let LookbackTime = 7d;
let MgmtPaths = dynamic([
    "\\Windows\\CCM\\",
    "\\Program Files (x86)\\Microsoft Intune Management Extension\\",
    "\\Program Files\\Microsoft Monitoring Agent\\",
    "\\Windows\\System32\\GroupPolicy\\"
]);
DeviceProcessEvents
| where TimeGenerated > ago(LookbackTime)
| where FileName in~ (
    "certutil.exe", "bitsadmin.exe", "regsvr32.exe", "rundll32.exe",
    "mshta.exe", "installutil.exe", "regasm.exe", "regsvcs.exe",
    "cmstp.exe", "odbcconf.exe", "msxsl.exe", "wmic.exe",
    "forfiles.exe", "pcalua.exe", "msbuild.exe", "presentationhost.exe",
    "msdt.exe", "hh.exe", "ieexec.exe", "xwizard.exe", "diskshadow.exe"
)
// Strip the binary's own name so its ".exe" doesn't self-match
| extend CmdArgs = replace_regex(ProcessCommandLine, @'(?i)^\s*"?[^"]*?\.exe"?', "")
| extend LowerArgs = tolower(CmdArgs)
| extend Technique = case(
    // --- certutil: download / decode (highest confidence) ---
    FileName =~ "certutil.exe" and LowerArgs has_any ("-urlcache", "urlcache", "-verifyctl", "verifyctl")
        and LowerArgs has_any ("http://", "https://", "ftp://"),
        "🔴 certutil Download",
    FileName =~ "certutil.exe" and LowerArgs has_any ("-decode", "decode", "-encode", "encode"),
        "🔴 certutil Encode/Decode",
    // --- regsvr32 Squiblydoo: remote scriptlet execution ---
    FileName =~ "regsvr32.exe" and LowerArgs has_any ("scrobj.dll", "/i:http", "/i:ftp", "i:http"),
        "🔴 regsvr32 Squiblydoo (remote scriptlet)",
    FileName =~ "regsvr32.exe" and LowerArgs has_any ("http://", "https://"),
        "🔴 regsvr32 Remote Load",
    // --- mshta: remote or inline script execution ---
    FileName =~ "mshta.exe" and LowerArgs has_any ("http://", "https://", "javascript:", "vbscript:"),
        "🔴 mshta Remote/Inline Script",
    // --- rundll32 abuse patterns ---
    FileName =~ "rundll32.exe" and LowerArgs has_any ("javascript:", "vbscript:", "mshtml"),
        "🔴 rundll32 Script Protocol",
    FileName =~ "rundll32.exe" and LowerArgs has "comsvcs" and LowerArgs has "minidump",
        "🔴 rundll32 comsvcs LSASS Dump",
    FileName =~ "rundll32.exe" and LowerArgs has_any ("url.dll", "openurl", "shell32.dll,shellexec"),
        "🟠 rundll32 URL/Shell Execution",
    FileName =~ "rundll32.exe" and LowerArgs matches regex
        @"(?i)[a-z]:\\(?:users|programdata|windows\\temp)\\[^,]*\.(?:dll|tmp|dat|log|txt|png|jpg),",
        "🔴 rundll32 DLL from User-Writable Path",
    // --- bitsadmin: background transfer ---
    FileName =~ "bitsadmin.exe" and LowerArgs has_any ("/transfer", "/addfile", "/create", "transfer"),
        "🔴 bitsadmin Transfer",
    // --- .NET LOLBins: proxy execution of managed assemblies ---
    FileName in~ ("installutil.exe", "regasm.exe", "regsvcs.exe")
        and LowerArgs has_any ("/logfile=", "/u ", "/logtoconsole=false", ".dll", ".exe"),
        "🔴 .NET LOLBin Proxy Execution",
    // --- msbuild inline task ---
    FileName =~ "msbuild.exe" and LowerArgs has_any (".xml", ".csproj", ".proj", ".targets")
        and not(InitiatingProcessFolderPath has_any (MgmtPaths)),
        "🟠 msbuild Project Execution",
    // --- wmic XSL execution ---
    FileName =~ "wmic.exe" and LowerArgs has_any ("/format:http", "/format:\\\\", "format:http"),
        "🔴 wmic Remote XSL Execution",
    // --- cmstp / odbcconf / msxsl ---
    FileName =~ "cmstp.exe" and LowerArgs has_any (".inf", "/s", "/ns"),
        "🔴 cmstp INF Execution",
    FileName =~ "odbcconf.exe" and LowerArgs has_any ("/a", "regsvr", ".rsp"),
        "🔴 odbcconf DLL Registration",
    FileName =~ "msxsl.exe",
        "🟠 msxsl XSL Execution",
    // --- process launchers used to break parent-child chains ---
    FileName in~ ("forfiles.exe", "pcalua.exe", "xwizard.exe")
        and LowerArgs has_any ("/c ", "-a ", "runwizard", ".exe", "cmd", "powershell"),
        "🟠 Process Launcher Proxy",
    // --- msdt (Follina-class) ---
    FileName =~ "msdt.exe" and LowerArgs has_any ("ms-msdt", "it_rebrowseforfile", "it_browseforfile"),
        "🔴 msdt Diagnostic Abuse",
    // --- diskshadow scripted mode ---
    FileName =~ "diskshadow.exe" and LowerArgs has_any ("/s ", "-s "),
        "🟠 diskshadow Script Mode",
    "⚪ Other"
)
| where Technique != "⚪ Other"
// Exclude signed management tooling running these legitimately
| where not(InitiatingProcessFolderPath has_any (MgmtPaths))
// --- Supporting context ---
| extend
    HasUrl = CmdArgs has_any ("http://", "https://", "ftp://"),
    HasUncPath = CmdArgs contains "\\\\",
    FromUserWritable = FolderPath has_any (
        "\\Temp\\", "\\AppData\\", "\\Downloads\\", "\\Public\\", "\\ProgramData\\"),
    SuspiciousParent = InitiatingProcessFileName in~ (
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe",
        "wscript.exe", "cscript.exe", "mshta.exe", "chrome.exe", "msedge.exe"),
    IsElevated = ProcessIntegrityLevel in ("High", "System"),
    IsHighConfidence = Technique startswith "🔴"
| extend RiskScore = 4
                   + (toint(IsHighConfidence) * 3)
                   + (toint(SuspiciousParent) * 4)
                   + (toint(HasUrl) * 2)
                   + (toint(FromUserWritable) * 2)
                   + (toint(HasUncPath) * 1)
                   + (toint(IsElevated) * 1)
| extend Severity = case(
    RiskScore >= 11, "🔴 Critical",
    RiskScore >= 8,  "🟠 High",
    RiskScore >= 6,  "🟡 Medium",
    "🟢 Low"
)
| summarize
    FirstSeen       = min(TimeGenerated),
    LastSeen        = max(TimeGenerated),
    OccurrenceCount = count(),
    Commands        = make_set(substring(CmdArgs, 0, 250), 3),
    Devices         = dcount(DeviceName)
    by Severity, RiskScore, Technique, IsHighConfidence,
       DeviceName, Account = AccountName, LolBin = FileName,
       ParentProcess = InitiatingProcessFileName,
       SuspiciousParent, HasUrl, FromUserWritable
| project
    FirstSeen,
    Severity,
    OccurrenceCount,
    Technique,
    DeviceName,
    Account,
    LolBin,
    ParentProcess,
    SuspiciousParent,
    HasUrl,
    FromUserWritable,
    Commands,
    RiskScore,
    IsHighConfidence,
    LastSeen
| sort by RiskScore desc, OccurrenceCount desc
```

---

## 📚 Reference

MITRE ATT&CK: T1218 (System Binary Proxy Execution), T1218.005 (Mshta), T1218.010 (Regsvr32), T1218.011 (Rundll32), T1105 (Ingress Tool Transfer), T1140 (Deobfuscate/Decode Files or Information), T1197 (BITS Jobs), T1003.001 (LSASS Memory), T1127.001 (Trusted Developer Utilities: MSBuild), T1220 (XSL Script Processing).
