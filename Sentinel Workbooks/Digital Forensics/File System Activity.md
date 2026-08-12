
```
// ============================================================
// FORENSICS: File System Activity Timeline
// ============================================================
// All file creates, modifies, renames, and deletes in the window.
// FileOriginUrl carries download provenance (Mark-of-the-Web equivalent),
// which is often the only surviving record of where a payload came from.
// PARAMETERS: {DeviceName}, {TimeRange}
// ============================================================
let TargetDevice = "{DeviceName}";
DeviceFileEvents
| where TimeGenerated {TimeRange}
| where isempty(TargetDevice) or DeviceName has TargetDevice
| extend
    WasDownloaded = iff(isnotempty(FileOriginUrl), "YES", ""),
    IsExecutable = iff(FileName has_any (".exe", ".dll", ".sys", ".scr",
        ".com", ".pif", ".msi", ".ocx"), "YES", ""),
    IsScript = iff(FileName has_any (".ps1", ".bat", ".cmd", ".vbs", ".vbe",
        ".js", ".jse", ".wsf", ".hta", ".py", ".sh"), "YES", ""),
    IsArchive = iff(FileName has_any (".zip", ".rar", ".7z", ".iso", ".img",
        ".cab", ".gz", ".tar"), "YES", ""),
    UserWritablePath = iff(FolderPath has_any (
        "\\Temp\\", "\\AppData\\", "\\Downloads\\", "\\Public\\",
        "\\ProgramData\\"), "YES", "")
| project
    TimeGenerated,
    DeviceName,
    Action = ActionType,
    FileName,
    FolderPath,
    IsExecutable,
    IsScript,
    IsArchive,
    UserWritablePath,
    WasDownloaded,
    FileOriginUrl,
    FileOriginReferrerUrl,
    Account = InitiatingProcessAccountName,
    ByProcess = InitiatingProcessFileName,
    ByProcessCmd = InitiatingProcessCommandLine,
    SHA256,
    FileSize
| sort by TimeGenerated asc
```
