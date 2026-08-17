# 🗂️ File System Activity Timeline

**Reconstructs every file create, modify, rename, and delete on a target device inside a time window — with download provenance intact.**

---

## 🎯 Purpose

When you're investigating a compromised endpoint, the file system is where the story lives. Payloads land, scripts get staged, archives get expanded, artifacts get cleaned up. Recovering that sequence tells you what the attacker touched, in what order, and — critically — *where it came from*.


---

## 🔍 How it works

| Step | Logic |
| --- | --- |
| 1️⃣ | Filter `DeviceFileEvents` to the target device and time window |
| 2️⃣ | Tag `WasDownloaded` when `FileOriginUrl` is populated |
| 3️⃣ | Tag `IsExecutable` for PE-family extensions (8 types) |
| 4️⃣ | Tag `IsScript` for interpreter-executed extensions (11 types) |
| 5️⃣ | Tag `IsArchive` for container formats — often used for payload staging (8 types) |
| 6️⃣ | Tag `UserWritablePath` when the write lands in a low-privilege writable directory |
| 7️⃣ | Project the full timeline with initiating process, account, and hash |
| 8️⃣ | Sort ascending — the story reads top to bottom |

---

## ⚖️ Risk signals surfaced

- **Executable in user-writable path** — classic drop location for malware avoiding admin rights
- **Script in Temp or AppData** — living-off-the-land staging pattern
- **Archive extraction to Downloads or Temp** — payload unpacking, often ISO/ZIP delivered via phish
- **`FileOriginUrl` present on suspicious extension** — direct link between download source and dropped file
- **Unusual `InitiatingProcessFileName`** — `mshta.exe`, `wscript.exe`, `certutil.exe`, `bitsadmin.exe` writing executables

---

---

## 🔍 KQL

```kql
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

## 📚 Reference

MITRE ATT&CK: T1105 (Ingress Tool Transfer), T1204.002 (User Execution: Malicious File), T1140 (Deobfuscate/Decode Files or Information), T1027 (Obfuscated Files or Information), T1074.001 (Data Staged: Local Data Staging).
