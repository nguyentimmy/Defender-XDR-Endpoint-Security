# 🔒 Persistence & Autoruns Inventory

**Inventories every persistence mechanism touched on a device — registry autoruns, scheduled tasks, services, startup folders, WMI subscriptions, and driver loads.**

---

## 🎯 Purpose

Persistence is how an attacker survives a reboot. Every intrusion that lasts more than a session leaves a footprint in one of a handful of well-known persistence locations, and this query pulls them all into one view.

This is deliberately an **inventory, not a detection** — no scoring, no exclusions of "normal" activity. You want to see every autorun key set, every scheduled task created, every service installed, and every driver loaded during the window so you can spot the one that doesn't belong. Legitimate software uses these mechanisms constantly; attackers hide in the noise.

---

## 🔍 How it works

| Step | Logic |
| --- | --- |
| 1️⃣ | Pull `DeviceRegistryEvents` for writes to known autorun keys (Run, RunOnce, Winlogon, Services, AppInit_DLLs, IFEO) |
| 2️⃣ | Pull `DeviceFileEvents` for writes to the Startup folder |
| 3️⃣ | Pull `DeviceProcessEvents` for command lines invoking `schtasks`, `sc create`, `New-Service`, `Register-WmiEvent`, or CIM/WMI subscription cmdlets |
| 4️⃣ | Pull `DeviceEvents` for native `ScheduledTaskCreated`, `ServiceInstalled`, and `WmiBindEventFilterToConsumer` events |
| 5️⃣ | Pull `DeviceImageLoadEvents` for `.sys` driver loads, flagging any outside standard driver paths |
| 6️⃣ | Union all five streams into a normalized schema and sort ascending |

---

## ⚖️ Risk signals surfaced

- **Autorun value pointing to a user-writable path** — Run keys should point to `Program Files`, not `AppData` or `Temp`
- **Scheduled task or service created by a script host** — `powershell.exe` or `wscript.exe` creating persistence is rarely legitimate
- **WMI event subscription** — fileless persistence technique, almost never used by legitimate software outside management tooling
- **Driver load from `[NON-STANDARD PATH]`** — BYOVD indicator; legitimate drivers live in the driver store, not `Temp` or `AppData`
- **IFEO (Image File Execution Options) modification** — classic debugger-hijack persistence, high-signal
- **Service creation followed by immediate start** — attacker installing and launching a persistence mechanism in one shot
- **Startup folder write by a browser or archive extractor** — legitimate installers don't drop directly into Startup

---

## 🔍 KQL

```kql
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
---

## 📚 Reference

MITRE ATT&CK: T1547.001 (Registry Run Keys / Startup Folder), T1053.005 (Scheduled Task), T1543.003 (Windows Service), T1546.003 (WMI Event Subscription), T1546.008 (Accessibility Features), T1546.012 (IFEO Injection), T1547.006 (Kernel Modules and Extensions), T1014 (Rootkit).