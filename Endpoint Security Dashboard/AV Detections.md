## 🦠 AV Detections

**Defender antivirus detections weighted by remediation outcome.**

A detection isn't automatically a resolved detection. This panel separates threats that were actually cleaned from those that were detected but left in place.

- `NotRemediated` — detected but remediation failed, was allowed, or didn't complete
- `WasRunning` — the threat was executing at detection time
- `IsHighImpactFamily` — ransomware, backdoors, RATs, credential-theft tooling, loaders
- Execution from user-writable paths adds weight

**The row that matters:** a high-impact family that was **running** and **not remediated** is a live infection, not a caught one — that's the trigger to pivot into device triage.

// ============================================================
// Antivirus Detections - Dashboard View
// ============================================================
// Defender AV detections with remediation outcome. Severity weights
// whether the threat was actually remediated vs. still present, plus
// threat family and execution path.
// ============================================================
let LookupTime = 14d;
DeviceEvents
| where Timestamp > ago(LookupTime)
| where ActionType in ("AntivirusDetection", "AntivirusReport", "AntivirusDetectionReport")
| extend Fields = parse_json(AdditionalFields)
| extend
    ThreatName = tostring(Fields.ThreatName),
    WasRemediated = tostring(Fields.WasRemediated),
    WasExecutingWhileDetected = tostring(Fields.WasExecutingWhileDetected),
    RemediationAction = tostring(Fields.RemediationAction),
    Severity_AV = tostring(Fields.Severity)
| extend
    NotRemediated = WasRemediated =~ "false" or RemediationAction has_any ("Allowed", "NotRemediated", "Failed"),
    WasRunning = WasExecutingWhileDetected =~ "true",
    IsHighImpactFamily = ThreatName has_any (
        "Ransom", "Backdoor", "Trojan:Win32/Mimikatz", "Rootkit",
        "HackTool", "Exploit", "Cobalt", "Meterpreter", "Emotet",
        "Qakbot", "AsyncRAT", "RedLine", "Lumma", "Vidar", "Amadey"
    ),
    RanFromSuspiciousPath = FolderPath has_any (
        "\\Temp\\", "\\AppData\\", "\\Downloads\\", "\\Public\\",
        "\\ProgramData\\", "\\Users\\Public\\", "\\PerfLogs\\"
    )
| extend RiskScore = 3
                   + (toint(NotRemediated) * 4)
                   + (toint(WasRunning) * 3)
                   + (toint(IsHighImpactFamily) * 3)
                   + (toint(RanFromSuspiciousPath) * 1)
| extend Severity = case(
    RiskScore >= 10, "🔴 Critical",
    RiskScore >= 7, "🟠 High",
    RiskScore >= 5, "🟡 Medium",
    "🟢 Low"
)
| summarize
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    DetectionCount = count(),
    AffectedDevices = dcount(DeviceName),
    Paths = make_set(FolderPath, 5),
    Files = make_set(FileName, 5)
    by Severity, RiskScore, ThreatName, DeviceName, AccountName = InitiatingProcessAccountName,
       WasRemediated, WasExecutingWhileDetected, RemediationAction,
       NotRemediated, WasRunning, IsHighImpactFamily, RanFromSuspiciousPath, SHA256
| project
    FirstSeen,
    Severity,
    DetectionCount,
    ThreatName,
    DeviceName,
    AccountName,
    WasRemediated,
    WasExecutingWhileDetected,
    RemediationAction,
    NotRemediated,
    WasRunning,
    IsHighImpactFamily,
    RanFromSuspiciousPath,
    Files,
    Paths,
    SHA256,
    RiskScore,
    LastSeen
| sort by RiskScore desc, DetectionCount desc