# 🧬 DLL / Image Load Timeline

**Surfaces DLL sideloading — a signed legitimate binary loading an unsigned module from a user-writable path.**

---

## 🎯 Purpose

Process-creation telemetry can't catch sideloading. The process itself looks clean — signed, from a legitimate install path, launched by a normal parent. The malicious code lives entirely in a DLL loaded at runtime, often from a user-writable directory the attacker planted it in.

This query pulls the full image load record and flags the sideloading signature: a **loader in a system path** pulling a **module from a user-writable one**. When scoped to a single device it shows every load for full context; run fleet-wide, it filters down to anomalies.

---

## 🔍 How it works

| Step | Logic |
| --- | --- |
| 1️⃣ | Pull `DeviceImageLoadEvents` for the target device and time window |
| 2️⃣ | Classify `ModuleType` — Driver, DLL, Executable, or Other |
| 3️⃣ | Tag `FromUserWritable` when the module sits in a low-privilege writable path |
| 4️⃣ | Tag `OutsideSystemPath` when the module isn't under System32, WinSxS, Program Files, etc. |
| 5️⃣ | Tag `LoaderFromSystemPath` when the initiating process lives in a trusted location |
| 6️⃣ | Flag `PossibleSideload = ⚠️ YES` when a system-path loader pulls a user-writable module |
| 7️⃣ | Fleet-wide: keep only anomalies. Device-scoped: keep everything for context |
| 8️⃣ | Sort ascending — load sequence reads top to bottom |

---

## ⚖️ Risk signals surfaced

- **`PossibleSideload = ⚠️ YES`** — the core detection; trusted binary loading untrusted code
- **`.sys` driver from `[NON-STANDARD PATH]`** — BYOVD indicator, kernel-level compromise potential
- **Module `FromUserWritable = YES` with generic name** — DLLs named `version.dll`, `wininet.dll`, `secur32.dll` in AppData or Temp are classic sideload targets
- **`LoadedBy` is a signed Microsoft binary** but module is unsigned — most damaging sideloads use legitimate signed loaders as cover
- **Loader in `Program Files` vendor folder** loading a module from `AppData\Local\Temp` — attacker dropped payload next to a real install path
- **Multiple sideload flags in short succession** — staged loader chain, common in modular malware

---

## 🔍 KQL

```kql
// ============================================================
// FORENSICS: DLL / Image Load Timeline
// ============================================================
// Catches DLL sideloading - a signed legitimate binary loading an
// unsigned module from a user-writable path. Invisible in process-creation
// telemetry, since the process itself looks clean; the malicious code lives
// entirely in the loaded DLL.
// PARAMETERS: {DeviceName}, {TimeRange}
// ============================================================
let TargetDevice = "{DeviceName}";
let SystemModulePaths = dynamic([
    "\\Windows\\System32\\",
    "\\Windows\\SysWOW64\\",
    "\\Windows\\WinSxS\\",
    "\\Windows\\assembly\\",
    "\\Windows\\Microsoft.NET\\",
    "\\Program Files\\",
    "\\Program Files (x86)\\"
]);
DeviceImageLoadEvents
| where TimeGenerated {TimeRange}
| where isempty(TargetDevice) or DeviceName has TargetDevice
| extend
    ModuleType = case(
        FileName endswith ".sys", "Driver",
        FileName endswith ".dll", "DLL",
        FileName endswith ".exe", "Executable",
        "Other"),
    FromUserWritable = iff(FolderPath has_any (
        "\\Temp\\", "\\AppData\\", "\\Downloads\\", "\\Public\\",
        "\\ProgramData\\", "\\Users\\"), "YES", ""),
    OutsideSystemPath = iff(not(FolderPath has_any (SystemModulePaths)), "YES", "")
// Sideloading signature: a binary living in a system path loading a module
// from a user-writable one
| extend LoaderFromSystemPath = iff(
    InitiatingProcessFolderPath has_any (SystemModulePaths), "YES", "")
| extend PossibleSideload = iff(
    FromUserWritable == "YES" and LoaderFromSystemPath == "YES", "⚠️ YES", "")
// Fleet-wide, show only anomalies; scoped to a device, show everything
| where OutsideSystemPath == "YES" or isnotempty(TargetDevice)
| project
    TimeGenerated,
    DeviceName,
    PossibleSideload,
    ModuleType,
    Module = FileName,
    ModulePath = FolderPath,
    FromUserWritable,
    OutsideSystemPath,
    LoadedBy = InitiatingProcessFileName,
    LoaderPath = InitiatingProcessFolderPath,
    LoaderCmd = InitiatingProcessCommandLine,
    Account = InitiatingProcessAccountName,
    ModuleSHA256 = SHA256,
    LoaderSHA256 = InitiatingProcessSHA256
| sort by TimeGenerated asc
```

---

## 📚 Reference

MITRE ATT&CK: T1574.001 (Hijack Execution Flow: DLL Search Order Hijacking), T1574.002 (DLL Side-Loading), T1055.001 (Process Injection: DLL Injection), T1055.002 (Portable Executable Injection), T1620 (Reflective Code Loading), T1014 (Rootkit).