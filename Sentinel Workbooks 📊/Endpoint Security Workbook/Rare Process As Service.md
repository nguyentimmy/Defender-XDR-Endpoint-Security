## ⚙️ Rare Process as Service

**Surfaces uncommon child processes of `services.exe`.**

Service creation is a durable persistence method that survives reboots and runs as SYSTEM. This panel baselines what normally spawns from the service host and flags the outliers — processes appearing fewer than six times per device and absent from a known-good watchlist.

- Enriched with network connections, file modifications, and DLL loads per process
- Severity weights execution from user-writable paths plus external network egress
- Requires a populated `KnownProcesses` watchlist to be meaningful

**Severity:** suspicious path + external network = High. Either alone = Medium.

```
// ============================================================
// Rare Service Processes - services.exe Uncommon Children
// ============================================================
// Processes spawned by services.exe not on the KnownProcesses watchlist
// and occurring rarely (<6 per device), enriched with network, file, and
// DLL activity. Requires _GetWatchlist('KnownProcesses') to be populated.
// ============================================================
let LookupTime = 7d;
let normalize = (name:string) { replace_string(tolower(name), " ", "") };
let WhiteList = materialize(_GetWatchlist('KnownProcesses') | project ProcessName = tolower(replace_string(trim(" ", tostring(processName)), " ", "")));
let KnownProc = toscalar(WhiteList | summarize make_set(ProcessName));
let GetServices = materialize (
DeviceProcessEvents
| where TimeGenerated > ago(LookupTime)
| where InitiatingProcessParentFileName contains "services.exe"
| where not(normalize(InitiatingProcessFileName) has_any (KnownProc))
| project TimeGenerated, DeviceName, StartedChildProcess = FileName, StartedChildProcessSHA1 = SHA1, StartedChildProcessCmdline = ProcessCommandLine, ServiceProcessSHA1 = InitiatingProcessSHA1, ServiceProcess = InitiatingProcessFileName, ServiceProcessCmdline = InitiatingProcessCommandLine, ServiceProcessID = InitiatingProcessId, ServiceProcessCreationTime = InitiatingProcessCreationTime, ServiceProcessUser = InitiatingProcessAccountName, ServiceProcessFolderPath = InitiatingProcessFolderPath
);
GetServices
| summarize RunCount = count() by ServiceProcess, DeviceName
| where RunCount < 6
| join kind = inner GetServices on ServiceProcess, DeviceName
| join kind = leftouter (
DeviceNetworkEvents
| where TimeGenerated > ago(LookupTime)
| where InitiatingProcessParentFileName contains "services.exe"
| where not(normalize(InitiatingProcessFileName) has_any (KnownProc))
| project TimeGenerated, DeviceName, ServiceProcessSHA1 = InitiatingProcessSHA1, ServiceProcess = InitiatingProcessFileName, ServiceProcessCmdline = InitiatingProcessCommandLine, ServiceProcessID = InitiatingProcessId, ServiceProcessCreationTime = InitiatingProcessCreationTime, ServiceProcessUser = InitiatingProcessAccountName, NetworkAction = ActionType, RemoteIP, RemoteUrl
) on DeviceName, ServiceProcess, ServiceProcessCmdline, ServiceProcessCreationTime, ServiceProcessID, ServiceProcessUser, ServiceProcessSHA1
| join kind = leftouter (
DeviceFileEvents
| where TimeGenerated > ago(LookupTime)
| where InitiatingProcessParentFileName contains "services.exe"
| where not(normalize(InitiatingProcessFileName) has_any (KnownProc))
| project TimeGenerated, DeviceName, ServiceProcessSHA1 = InitiatingProcessSHA1, ServiceProcess = InitiatingProcessFileName, ServiceProcessCmdline = InitiatingProcessCommandLine, ServiceProcessID = InitiatingProcessId, ServiceProcessCreationTime = InitiatingProcessCreationTime, ServiceProcessUser = InitiatingProcessAccountName, FileAction = ActionType, ModifiedFile = FileName, ModifiedFileSHA1 = SHA1, ModifiedFilePath = FolderPath
) on DeviceName, ServiceProcess, ServiceProcessCmdline, ServiceProcessCreationTime, ServiceProcessID, ServiceProcessUser, ServiceProcessSHA1
| join kind = leftouter (
DeviceImageLoadEvents
| where TimeGenerated > ago(LookupTime)
| where InitiatingProcessParentFileName contains "services.exe"
| where not(normalize(InitiatingProcessFileName) has_any (KnownProc))
| project TimeGenerated, DeviceName, ServiceProcessSHA1 = InitiatingProcessSHA1, ServiceProcess = InitiatingProcessFileName, ServiceProcessCmdline = InitiatingProcessCommandLine, ServiceProcessID = InitiatingProcessId, ServiceProcessCreationTime = InitiatingProcessCreationTime, ServiceProcessUser = InitiatingProcessAccountName, LoadedDLL = FileName, LoadedDLLSHA1 = SHA1, LoadedDLLPath = FolderPath
) on DeviceName, ServiceProcess, ServiceProcessCmdline, ServiceProcessCreationTime, ServiceProcessID, ServiceProcessUser, ServiceProcessSHA1
| summarize FirstSeen = min(ServiceProcessCreationTime), ConnectedAddresses = make_set(RemoteIP, 100), ConnectedUrls = make_set(RemoteUrl, 100), FilesModified = make_set(ModifiedFile, 100), FileModFolderPath = make_set(ModifiedFilePath, 100), FileModSHA1s = make_set(ModifiedFileSHA1, 100), ChildProcesses = make_set(StartedChildProcess, 100), ChildCommandlines = make_set(StartedChildProcessCmdline, 100), DLLsLoaded = make_set(LoadedDLL, 100), DLLSHA1 = make_set(LoadedDLLSHA1, 100) by DeviceName, ServiceProcess, ServiceProcessCmdline, ServiceProcessCreationTime, ServiceProcessID, ServiceProcessUser, ServiceProcessSHA1, ServiceProcessFolderPath
// --- Risk signals for severity ---
| extend
    RanFromSuspiciousPath = ServiceProcessFolderPath has_any ("\\temp\\", "\\tmp\\", "\\appdata\\", "\\programdata\\", "\\public\\", "\\users\\", "\\downloads\\", "\\perflogs\\"),
    HasExternalNetwork = array_length(ConnectedAddresses) > 0 or array_length(ConnectedUrls) > 0,
    SpawnedChildren = array_length(ChildProcesses) > 0,
    ModifiedFiles = array_length(FilesModified) > 0
| extend Severity = case(
    RanFromSuspiciousPath and HasExternalNetwork, "🔴 High",
    RanFromSuspiciousPath or (HasExternalNetwork and SpawnedChildren), "🟠 Medium",
    "🟡 Low"
)
| project
    FirstSeen,
    Severity,
    DeviceName,
    ServiceProcess,
    ServiceProcessUser,
    ServiceProcessFolderPath,
    ServiceProcessCmdline,
    RanFromSuspiciousPath,
    HasExternalNetwork,
    ConnectedAddresses,
    ConnectedUrls,
    ChildProcesses,
    ChildCommandlines,
    FilesModified,
    FileModFolderPath,
    DLLsLoaded,
    ServiceProcessSHA1
| sort by Severity asc, FirstSeen desc
```
