
```
// ============================================================
// FORENSICS: Process Execution Timeline & Lineage
// ============================================================
// Complete process execution record for the scoped device and window.
// NO suppression - this is evidence, not detection. Walk backward from a
// payload through parent and grandparent to reach the initial execution.
// PARAMETERS: {DeviceName}, {TimeRange}
// ============================================================
let TargetDevice = "{DeviceName}";
DeviceProcessEvents
| where TimeGenerated {TimeRange}
| where isempty(TargetDevice) or DeviceName has TargetDevice
| extend
    Elevated = iff(ProcessIntegrityLevel in ("High", "System"), "YES", ""),
    RanFromUserWritable = iff(FolderPath has_any (
        "\\Temp\\", "\\AppData\\", "\\Downloads\\", "\\Public\\",
        "\\ProgramData\\", "\\Users\\"), "YES", ""),
    Signer = ProcessVersionInfoCompanyName,
    RenamedBinary = iff(isnotempty(ProcessVersionInfoOriginalFileName)
        and FileName !~ ProcessVersionInfoOriginalFileName, "YES", "")
| project
    TimeGenerated,
    DeviceName,
    Account = AccountName,
    Grandparent = InitiatingProcessParentFileName,
    Parent = InitiatingProcessFileName,
    Process = FileName,
    ProcessCommandLine,
    ParentCommandLine = InitiatingProcessCommandLine,
    FolderPath,
    Elevated,
    IntegrityLevel = ProcessIntegrityLevel,
    RanFromUserWritable,
    RenamedBinary,
    OriginalFileName = ProcessVersionInfoOriginalFileName,
    Signer,
    SHA256,
    ProcessId,
    ParentProcessId = InitiatingProcessId
| sort by TimeGenerated asc
```
