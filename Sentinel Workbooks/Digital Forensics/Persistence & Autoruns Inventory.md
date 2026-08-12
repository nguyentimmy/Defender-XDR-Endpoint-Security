

```
// ============================================================
// FORENSICS: Persistence & Autoruns Inventory
// ============================================================
// Every persistence mechanism touched in the window, presented as an
// inventory rather than a detection: autorun keys, scheduled tasks,
// services, Startup folder, WMI subscriptions, and loaded drivers.
// PARAMETERS: {DeviceName}, {TimeRange}
// ============================================================
let TargetDevice = "{DeviceName}";
let LegitDriverPaths = dynamic([
    "\\Windows\\System32\\drivers\\",
    "\\Windows\\System32\\DriverStore\\FileRepository\\",
    "\\Windows\\SysWOW64\\drivers\\"
]);
union isfuzzy=true
(
    DeviceRegistryEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
    | where RegistryKey has_any (
        "CurrentVersion\\Run", "CurrentVersion\\RunOnce",
        "CurrentVersion\\RunServices", "Policies\\Explorer\\Run",
        "Winlogon\\Shell", "Winlogon\\Userinit", "Winlogon\\Notify",
        "CurrentVersion\\Windows\\Load", "CurrentVersion\\Windows\\Run",
        "Image File Execution Options", "AppInit_DLLs",
        "CurrentControlSet\\Services", "CurrentVersion\\Explorer\\Shell Folders")
    | project
        TimeGenerated, DeviceName,
        Mechanism = "Registry Autorun",
        Artifact = strcat(RegistryValueName, " = ", substring(RegistryValueData, 0, 200)),
        Location = RegistryKey,
        Account = InitiatingProcessAccountName,
        ByProcess = InitiatingProcessFileName,
        ByProcessCmd = InitiatingProcessCommandLine,
        SHA256 = InitiatingProcessSHA256
),
(
    DeviceFileEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where ActionType in ("FileCreated", "FileModified", "FileRenamed")
    | where FolderPath has_any ("\\Start Menu\\Programs\\Startup\\",
        "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\")
    | project
        TimeGenerated, DeviceName,
        Mechanism = "Startup Folder",
        Artifact = FileName,
        Location = FolderPath,
        Account = InitiatingProcessAccountName,
        ByProcess = InitiatingProcessFileName,
        ByProcessCmd = InitiatingProcessCommandLine,
        SHA256
),
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | extend CmdArgs = replace_regex(ProcessCommandLine, @'(?i)^\s*"?[^"]*?\.exe"?', "")
    | where CmdArgs has_any ("schtasks /create", "New-ScheduledTask",
        "Register-ScheduledTask", "sc create", "sc.exe create", "New-Service",
        "Register-WmiEvent", "__EventFilter", "CommandLineEventConsumer",
        "Set-WmiInstance", "New-CimInstance")
    | extend Mechanism = case(
        CmdArgs has_any ("schtasks", "ScheduledTask"), "Scheduled Task",
        CmdArgs has_any ("sc create", "New-Service"), "Service Creation",
        "WMI Subscription")
    | project
        TimeGenerated, DeviceName, Mechanism,
        Artifact = substring(CmdArgs, 0, 250),
        Location = FolderPath,
        Account = AccountName,
        ByProcess = InitiatingProcessFileName,
        ByProcessCmd = InitiatingProcessCommandLine,
        SHA256
),
(
    DeviceEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where ActionType in ("WmiBindEventFilterToConsumer", "ScheduledTaskCreated",
        "ScheduledTaskUpdated", "ServiceInstalled")
    | project
        TimeGenerated, DeviceName,
        Mechanism = strcat("Native: ", ActionType),
        Artifact = substring(tostring(AdditionalFields), 0, 250),
        Location = "",
        Account = InitiatingProcessAccountName,
        ByProcess = InitiatingProcessFileName,
        ByProcessCmd = InitiatingProcessCommandLine,
        SHA256 = InitiatingProcessSHA256
),
(
    DeviceImageLoadEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where FileName endswith ".sys"
    | extend OddPath = iff(not(FolderPath has_any (LegitDriverPaths)), " [NON-STANDARD PATH]", "")
    | project
        TimeGenerated, DeviceName,
        Mechanism = "Driver Load",
        Artifact = strcat(FileName, OddPath),
        Location = FolderPath,
        Account = InitiatingProcessAccountName,
        ByProcess = InitiatingProcessFileName,
        ByProcessCmd = InitiatingProcessCommandLine,
        SHA256
)
| project TimeGenerated, DeviceName, Mechanism, Artifact, Location,
          Account, ByProcess, ByProcessCmd, SHA256
| sort by TimeGenerated asc
```
