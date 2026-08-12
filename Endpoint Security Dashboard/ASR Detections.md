## 🛡️ ASR Detections

**Attack Surface Reduction rule blocks, ranked by rule impact.**

ASR is prevention rather than detection — a hit means something was stopped. The value is in *which* rule fired, since that indicates what the attacker was attempting.

- Severity assigned per rule rather than uniformly: ransomware, email-executable, Office-child-process, and vulnerable-driver blocks rank highest
- Injection, obfuscated-script, and untrusted-executable blocks rank medium
- Environment-specific noisy rules and known-good processes are excluded

// ============================================================
// ASR Rule Blocks - Dashboard View (Severity Enriched)
// ============================================================
// ASR rule blocks by device/file/process, excluding the noisy LSASS rule
// and known-good dmclientprt.exe. Severity by per-rule attack impact.
// ============================================================
DeviceEvents
| where Timestamp > ago(14d)
| where ActionType startswith "Asr"
| where ActionType contains "Block"
| where ActionType != "AsrLsassCredentialTheftBlocked"
| where FileName !~ "dmclientprt.exe"
// --- Assign severity by ASR rule impact ---
| extend Severity = case(
    ActionType has_any (
        "AsrRansomware",
        "AsrExecutableEmailContentBlocked",
        "AsrOfficeChildProcessBlocked",
        "AsrScriptExecutableDownloadBlocked",
        "AsrPsexecWmiChildProcessBlocked",
        "AsrVulnerableSignedDriverBlocked",
        "AsrLsassCredentialTheft"
    ), "🔴 High",
    ActionType has_any (
        "AsrOfficeProcessInjectionBlocked",
        "AsrProcessInjection",
        "AsrObfuscatedScriptBlocked",
        "AsrScriptExecutableBlocked",
        "AsrUntrustedExecutableBlocked",
        "AsrUntrustedUsbProcessBlocked",
        "AsrAdobeReaderChildProcessBlocked"
    ), "🟠 Medium",
    "🟡 Low"
)
| summarize
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    HitCount = count()
    by Severity,
       ActionType,
       DeviceName,
       FileName,
       InitiatingProcessCommandLine,
       InitiatingProcessFileName,
       FolderPath,
       InitiatingProcessFolderPath,
       SHA256
| project
    FirstSeen,
    Severity,
    HitCount,
    LastSeen,
    ActionType,
    DeviceName,
    FileName,
    InitiatingProcessCommandLine,
    InitiatingProcessFileName,
    FolderPath,
    InitiatingProcessFolderPath,
    SHA256
| sort by Severity asc, HitCount desc