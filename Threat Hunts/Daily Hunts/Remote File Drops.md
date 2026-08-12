
```
// ============================================================
// PSEXEC LATERAL MOVEMENT - Mass Remote File Drops
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