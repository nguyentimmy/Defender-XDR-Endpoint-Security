
```
// ============================================================
// FORENSICS: Logon & Session Timeline
// ============================================================
// Complete authentication record - the attribution panel. Answers which
// account was present on the host when the activity in the other panels
// occurred, and is the pivot point into user-side investigation.
// PARAMETERS: {DeviceName}, {TimeRange}
// ============================================================
let TargetDevice = "{DeviceName}";
DeviceLogonEvents
| where TimeGenerated {TimeRange}
| where isempty(TargetDevice) or DeviceName has TargetDevice
| extend
    Result = ActionType,
    IsRemote = iff(LogonType in ("RemoteInteractive", "Network", "NetworkCleartext"), "YES", ""),
    IsRdp = iff(LogonType == "RemoteInteractive", "YES", ""),
    FromExternalIP = iff(RemoteIPType == "Public", "YES", ""),
    Source = coalesce(RemoteIP, RemoteDeviceName, "local")
| project
    TimeGenerated,
    DeviceName,
    Result,
    Account = AccountName,
    AccountDomain,
    LogonType,
    IsRdp,
    IsRemote,
    FromExternalIP,
    Source,
    RemoteIP,
    RemoteDeviceName,
    LocalAdmin = tostring(IsLocalAdmin),
    Protocol,
    ByProcess = InitiatingProcessFileName,
    ByProcessCmd = InitiatingProcessCommandLine,
    FailureReason
| sort by TimeGenerated asc
```
