# 🌲 Process Execution Timeline & Lineage

**Complete process execution record for a device — every process, its parent, and its grandparent, with no suppression.**

---

## 🎯 Purpose

Payloads don't run in isolation. Every malicious process was launched by something, and that something was launched by something else. Walking that chain backward from the payload — through parent to grandparent to the initial entry point — is how you find the actual root cause of a compromise.

This is deliberately unfiltered. No baseline exclusions, no "known good" suppressions. This is evidence, not detection — you want the complete execution record so you can trace lineage without wondering what got filtered out.

---

## 🔍 How it works

| Step | Logic |
| --- | --- |
| 1️⃣ | Pull `DeviceProcessEvents` for the target device and time window |
| 2️⃣ | Tag `Elevated` when integrity level is `High` or `System` |
| 3️⃣ | Tag `RanFromUserWritable` when the binary sits in a low-privilege writable path |
| 4️⃣ | Tag `RenamedBinary` when `FileName` doesn't match the PE's `OriginalFileName` metadata |
| 5️⃣ | Surface `Grandparent → Parent → Process` for three-generation lineage in one row |
| 6️⃣ | Project full command lines for both process and parent — the story is in the arguments |
| 7️⃣ | Sort ascending — execution sequence reads top to bottom |

---

## ⚖️ Risk signals surfaced

- **`RenamedBinary = YES`** — attacker renamed a known tool to blend in; `svchost.exe` in Temp with `OriginalFileName = mimikatz.exe` is the classic tell
- **Office app as `Parent`** — `winword.exe`, `excel.exe`, `outlook.exe` spawning `powershell.exe`, `cmd.exe`, or `wscript.exe` is macro or exploit execution
- **Script host as `Parent`** — `powershell.exe`, `mshta.exe`, `wscript.exe` launching binaries, especially with `RanFromUserWritable = YES`
- **LOLBin chains** — `certutil.exe`, `bitsadmin.exe`, `regsvr32.exe`, `rundll32.exe` in the lineage, often with unusual arguments
- **`Elevated = YES` with unsigned or user-writable `Process`** — privilege escalation successful, or UAC bypass
- **Grandparent is `explorer.exe` and parent is a browser** — user clicked and ran something, trace the download in the file timeline
- **Empty `Signer`** — unsigned binary, worth scrutinizing especially outside standard install paths

---

## 🔍 KQL

```kql
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

---

## 📚 Reference

MITRE ATT&CK: T1059 (Command and Scripting Interpreter), T1036.003 (Rename System Utilities), T1036.005 (Match Legitimate Name or Location), T1218 (System Binary Proxy Execution), T1548 (Abuse Elevation Control Mechanism), T1055 (Process Injection), T1204 (User Execution).