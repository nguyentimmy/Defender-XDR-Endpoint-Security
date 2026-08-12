
# 🔀 PsExec Lateral Movement — Mass Remote File Drops

**Detects PsExec-style tools pushing multiple executables to remote machines over admin shares inside a short window.**

---

## 🎯 Purpose

PsExec is a legitimate Sysinternals admin tool, which is exactly why attackers use it. A single remote execution is unremarkable; **many binaries dropped to remote hosts in ten minutes** is not.

That volume-and-velocity pattern is the signal. It's the shape of lateral movement, mass tool deployment, and — most commonly — ransomware staging, where the operator pushes the payload to every reachable machine before detonating.

---

## 🔍 Detection logic

| Step | Logic |
| --- | --- |
| 1️⃣ | Filter `DeviceFileEvents` to PsExec-style command lines (`accepteula` is the classic tell) |
| 2️⃣ | Require a UNC destination — the file landed on a *remote* machine |
| 3️⃣ | Keep executable payloads only (`.exe`, `.bat`, `.cmd`, `.dll`) |
| 4️⃣ | Require multiple binaries or a batch script in the command line |
| 5️⃣ | Exclude known legitimate admin and management tooling |
| 6️⃣ | Bin into 10-minute windows per device, account, and process |
| 7️⃣ | Fire when distinct remote paths exceed the threshold |

Tunable: `FileThreshold` (4 distinct remote paths) and `TimeWindowBin` (10 minutes).


---

## ⚖️ Risk signals

| Signal | Weight | Meaning |
| --- | --- | --- |
| **Base — PsExec mass drop** | 3 | The pattern itself |
| 📁 **Suspicious path** | +1 | Landed in Temp, Public, or ProgramData |
| 🔓 **Admin share** | +1 | Written via `admin$`, `c$`, or `ipc$` |
| 🔥 **High file count** | +3 | More than 10 distinct remote paths |
| 🧬 **Many unique binaries** | +2 | More than 5 distinct hashes |

High file count plus many distinct hashes is the ransomware-staging profile — one operator, many targets, varied payloads.

---

## 🔍 KQL

```
// ============================================================
// PSEXEC LATERAL MOVEMENT - Mass Remote File Drops
// ============================================================
// MITRE ATT&CK:
//   Tactic:    Lateral Movement, Execution
//   Technique: T1570     - Lateral Tool Transfer
//              T1021.002 - Remote Services: SMB/Windows Admin Shares
//              T1569.002 - System Services: Service Execution
//              T1072     - Software Deployment Tools
// ============================================================
// Hunts for PsExec-style tools dropping multiple executables to remote
// machines (admin shares) within a 10-minute window — a strong indicator
// of lateral movement, mass tool deployment, or ransomware staging.
// ============================================================
let LookbackTime = 14d;
let FileThreshold = 4;          // min distinct remote paths in the window
let TimeWindowBin = 10m;
DeviceFileEvents
| where TimeGenerated > ago(LookbackTime)
// --- PsExec-style execution (accepteula is the classic tell) ---
| where InitiatingProcessCommandLine has_any (
    "accepteula",
    "psexec",
    "paexec",
    "-s -d",            // PsExec system + detached
    "\\\\*\\admin$",    // pushing to admin share
    "\\\\*\\c$"
)
// --- Dropped to a remote machine (UNC path) and is an executable ---
| where FolderPath has "\\\\"
| where FileName endswith ".exe" or FileName endswith ".bat" or FileName endswith ".cmd" or FileName endswith ".dll"
// --- Count executables referenced in the command line ---
| extend ExeCount = countof(InitiatingProcessCommandLine, ".exe")
| extend BatCount = countof(InitiatingProcessCommandLine, ".bat")
// --- Multiple binaries OR a batch script involved ---
| where (InitiatingProcessCommandLine !has ".ps1" and ExeCount > 1)
    or InitiatingProcessCommandLine has ".bat"
    or InitiatingProcessCommandLine has ".cmd"
// --- Exclusions (remove lines to widen scope) ---
| where not(InitiatingProcessCommandLine has_any (
    "batch", "auditpol", "script", "scripts",
    "illusive", "rebootrequired",
    "SccmClient", "ccmsetup", "MonitoringHost"   // common legit admin tools
))
// --- Flag suspicious indicators ---
| extend
    IsSuspiciousPath = FolderPath has_any (
        "\\temp\\", "\\tmp\\", "\\public\\",
        "\\windows\\temp\\", "\\programdata\\"
    ),
    IsAdminShare = FolderPath has_any ("admin$", "c$", "ipc$")
// --- Summarize per device per 10-min window ---
| summarize
    StartTime       = min(TimeGenerated),
    EndTime         = max(TimeGenerated),
    FileCount       = dcount(FolderPath),
    TotalEvents     = count(),
    DistinctHashes  = dcount(SHA1),
    Hashes          = make_set(SHA1, 50),
    Paths           = make_set(FolderPath, 50),
    Files           = make_set(FileName, 50),
    CommandLines    = make_set(InitiatingProcessCommandLine, 20),
    AnySuspiciousPath = max(IsSuspiciousPath),
    AnyAdminShare     = max(IsAdminShare)
    by DeviceId, DeviceName,
       TimeWindow = bin(TimeGenerated, TimeWindowBin),
       InitiatingProcessFileName,
       InitiatingProcessAccountName
// --- Only mass-drop events ---
| where FileCount > FileThreshold
// --- Risk Score ---
| extend RiskScore = 3                                  // base: PsExec mass drop
                   + toint(AnySuspiciousPath)
                   + toint(AnyAdminShare)
                   + iff(FileCount > 10, 3, 0)          // very high file count
                   + iff(DistinctHashes > 5, 2, 0)      // many unique binaries
| extend Severity = case(
    RiskScore >= 7, "🔴 Critical",
    RiskScore >= 5, "🟠 High",
    "🟡 Medium"
)
| project
    StartTime,
    EndTime,
    Severity,
    RiskScore,
    DeviceName,
    InitiatingProcessAccountName,
    InitiatingProcessFileName,
    FileCount,
    TotalEvents,
    DistinctHashes,
    AnySuspiciousPath,
    AnyAdminShare,
    Files,
    Paths,
    CommandLines,
    Hashes
// --- Entity mapping for analytics rules ---
| extend
    timestamp           = StartTime,
    HostCustomEntity    = DeviceName,
    AccountCustomEntity = InitiatingProcessAccountName
| sort by RiskScore desc, FileCount desc
```

---

## 📚 Reference

MITRE ATT&CK: T1570 (Lateral Tool Transfer), T1021.002 (Remote Services: SMB/Admin Shares), T1569.002 (System Services: Service Execution).
