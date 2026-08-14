# 🔥 Mass File Encryption — Ransomware Detonation in Progress

**Detects active ransomware execution — encryption bursts, multi-folder ransom notes, and mass deletion — as it's happening.**

---

## 🎯 Purpose

By the time a ransom note appears on a user's screen, you've already lost. This detection is the **last chance to isolate a host before a share is gone**. It targets the three telemetry signals ransomware generates in the seconds and minutes before impact is complete: a single process rewriting hundreds of files with a converging extension, ransom notes dropped across many folders, and mass file deletion typical of wipers or exfil-then-destroy operations.

Precision comes from three combined requirements — one process, many files across many folders, converging on a single novel extension. Legitimate bulk activity (installers, backup agents, OneDrive) touches many *different* extensions across many files; ransomware converges on one. That distinction is what keeps this precise enough to auto-isolate on.

**Deploy at the shortest scheduling interval your tier allows.** Minutes matter.

---

## 🔍 How it works

The query unions three independent branches. Any single branch firing is Critical — this is not a scored detection where signals must stack.

| Branch | Trigger |
| --- | --- |
| **Encryption burst** | One process modifies/renames/creates ≥ 100 files across ≥ 5 folders within 5 minutes, with ≤ 3 distinct new extensions (convergence) OR extension matches a known ransomware family |
| **Ransom note drop** | Same process drops files matching ransom-note naming patterns (`readme`, `how_to_decrypt`, `restore_files`, etc.) across ≥ 3 folders within 5 minutes |
| **Mass deletion** | One process deletes ≥ 100 files across ≥ 5 folders within 5 minutes, outside legitimate cleanup paths |

**Exclusions in every branch:** Windows Defender, TrustedInstaller, Windows Update, OneDrive, Dropbox, Google Drive, CCM/SCCM, installer processes. System paths (`WinSxS`, `servicing`, `SoftwareDistribution`, `WindowsApps`) are stripped so component churn doesn't fire the detection.

---

## ⚖️ Signals & scoring

Each branch fires at a fixed risk score. All three are Critical severity — this detection is designed to trigger automated response.

| Signal | Score | Meaning |
| --- | --- | --- |
| 🔴 **Known Ransomware Extension Burst** | 10 | Extension matches a known family (LockBit, Conti, BlackCat, Akira, Cl0p, etc.) — ransomware confirmed |
| 🔴 **Ransom Note Dropped (multi-folder)** | 10 | Ransom-note filename pattern appears across ≥ 3 folders from one process — impact reached |
| 🔴 **Mass Encryption Burst (novel extension)** | 9 | Bulk file changes converging on ≤ 3 extensions — likely ransomware with an unknown extension |
| 🔴 **Mass File Deletion** | 9 | Bulk deletes across many folders outside cleanup paths — wiper or destruction phase |

**Tunable thresholds** (top of query):

| Parameter | Default | Effect |
| --- | --- | --- |
| `TimeBin` | 5 min | Aggregation window per process |
| `FileBurstThreshold` | 100 | Minimum files touched to trigger |
| `DistinctFolderThreshold` | 5 | Minimum folders touched to trigger |
| `LookbackTime` | 7d | Historical scope |

Drop the file/folder thresholds only after tuning — ransomware easily clears 100/5, but so do some legit workflows. `TimeBin` at 5 minutes catches slower "low-and-slow" encryption while still bursting alerts fast enough to matter.

---

## 🔍 KQL

```kql
// ============================================================
// MASS FILE ENCRYPTION - Ransomware Detonation in Progress
// ============================================================
// MITRE ATT&CK:
//   Tactic:    Impact
//   Technique: T1486 - Data Encrypted for Impact
//              T1485 - Data Destruction
//              T1490 - Inhibit System Recovery
// ============================================================
// Detects active encryption: a burst of file modifications or renames by
// a single process, converging on a novel extension, plus ransom-note
// drops. This is the LAST chance to isolate before a share is lost -
// deploy at the shortest scheduling interval your tier allows.
// ============================================================
let LookbackTime = 7d;
let TimeBin = 5m;
let FileBurstThreshold = 100;
let DistinctFolderThreshold = 5;
let KnownRansomExtensions = dynamic([
    "lockbit", "conti", "ryuk", "revil", "sodinokibi", "blackcat", "alphv",
    "royal", "hive", "avoslocker", "quantum", "basta", "akira", "rhysida",
    "medusa", "cl0p", "clop", "phobos", "dharma", "wannacry", "wncry",
    "locky", "cerber", "crysis", "makop", "mallox", "8base", "playcrypt",
    "encrypted", "enc", "crypted", "crypt", "locked", "onion", "pay",
    "ransom", "nightsky", "blackbyte", "cuba", "vice", "zeppelin"
]);
let RansomNotePatterns = dynamic([
    "readme", "read_me", "read-me", "how_to_decrypt", "how-to-decrypt",
    "howtodecrypt", "decrypt_instruction", "decrypt-files", "restore_files",
    "restore-my-files", "recover_files", "recovery", "unlock_files",
    "your_files", "important.txt", "ransom", "!!!", "_help_", "help_decrypt",
    "attention", "warning.txt"
]);
union isfuzzy=true
// ============================================================
// 1. ENCRYPTION BURST - one process, many files, novel extension
// ============================================================
(
    DeviceFileEvents
    | where TimeGenerated > ago(LookbackTime)
    | where ActionType in ("FileRenamed", "FileModified", "FileCreated")
    | where isnotempty(InitiatingProcessFileName)
    // Ignore system/update churn that legitimately touches many files
    | where not(InitiatingProcessFileName in~ (
        "msmpeng.exe", "tiworker.exe", "trustedinstaller.exe", "wuauclt.exe",
        "onedrive.exe", "dropbox.exe", "googledrivesync.exe", "backupagent.exe",
        "ccmexec.exe", "setup.exe", "msiexec.exe", "sedsvc.exe"))
    | where not(FolderPath has_any (
        "\\Windows\\WinSxS\\", "\\Windows\\servicing\\", "\\Windows\\SoftwareDistribution\\",
        "\\Windows\\Installer\\", "\\Program Files\\WindowsApps\\"))
    | extend NewExtension = tolower(extract(@"\.([^.\\/]{1,12})$", 1, FileName))
    | summarize
        FileCount        = count(),
        DistinctFiles    = dcount(FileName),
        DistinctFolders  = dcount(FolderPath),
        DistinctExts     = dcount(NewExtension),
        TopExtensions    = make_set(NewExtension, 10),
        SampleFiles      = make_set(FileName, 5),
        SampleFolders    = make_set(FolderPath, 5),
        Actions          = make_set(ActionType, 3)
        by DeviceName,
           Account = InitiatingProcessAccountName,
           Process = InitiatingProcessFileName,
           ProcessCmd = InitiatingProcessCommandLine,
           TimeWindow = bin(TimeGenerated, TimeBin)
    | where FileCount >= FileBurstThreshold
    | where DistinctFolders >= DistinctFolderThreshold
    // Encryption converges on ONE new extension across many files.
    // Legitimate bulk activity touches many different extensions.
    | extend ExtensionConvergence = iff(DistinctExts <= 3, "YES", "")
    | extend MatchesKnownFamily = iff(
        tostring(TopExtensions) has_any (KnownRansomExtensions), "YES", "")
    | where ExtensionConvergence == "YES" or MatchesKnownFamily == "YES"
    | extend
        Signal = iff(MatchesKnownFamily == "YES",
            "🔴 Known Ransomware Extension Burst",
            "🔴 Mass Encryption Burst (novel extension)"),
        RiskScore = iff(MatchesKnownFamily == "YES", 10, 9),
        Detail = substring(strcat(
            "Files: ", tostring(FileCount),
            " | Folders: ", tostring(DistinctFolders),
            " | Ext: ", tostring(TopExtensions),
            " | Samples: ", tostring(SampleFiles)), 0, 400)
    | project TimeGenerated = TimeWindow, Signal, RiskScore, DeviceName,
              Account, Process, ProcessCmd, FileCount, DistinctFolders, Detail
),
// ============================================================
// 2. RANSOM NOTE DROPPED (fires regardless of volume)
// ============================================================
(
    DeviceFileEvents
    | where TimeGenerated > ago(LookbackTime)
    | where ActionType in ("FileCreated", "FileModified")
    | where FileName endswith ".txt" or FileName endswith ".hta"
        or FileName endswith ".html" or FileName endswith ".htm"
    | where tolower(FileName) has_any (RansomNotePatterns)
    // A note in many folders is the giveaway - one readme.txt is not
    | summarize
        NoteCount     = count(),
        FolderCount   = dcount(FolderPath),
        NoteNames     = make_set(FileName, 5),
        SampleFolders = make_set(FolderPath, 5)
        by DeviceName,
           Account = InitiatingProcessAccountName,
           Process = InitiatingProcessFileName,
           ProcessCmd = InitiatingProcessCommandLine,
           TimeWindow = bin(TimeGenerated, TimeBin)
    | where FolderCount >= 3
    | extend
        Signal = "🔴 Ransom Note Dropped (multi-folder)",
        RiskScore = 10,
        FileCount = NoteCount,
        DistinctFolders = FolderCount,
        Detail = substring(strcat(
            "Notes: ", tostring(NoteNames),
            " | Folders: ", tostring(FolderCount),
            " | Paths: ", tostring(SampleFolders)), 0, 400)
    | project TimeGenerated = TimeWindow, Signal, RiskScore, DeviceName,
              Account, Process, ProcessCmd, FileCount, DistinctFolders, Detail
),
// ============================================================
// 3. MASS DELETION (wiper / exfil-then-destroy)
// ============================================================
(
    DeviceFileEvents
    | where TimeGenerated > ago(LookbackTime)
    | where ActionType == "FileDeleted"
    | where not(InitiatingProcessFileName in~ (
        "msmpeng.exe", "tiworker.exe", "trustedinstaller.exe", "cleanmgr.exe",
        "onedrive.exe", "ccmexec.exe", "msiexec.exe", "explorer.exe"))
    | where not(FolderPath has_any (
        "\\Windows\\Temp\\", "\\Windows\\SoftwareDistribution\\",
        "\\AppData\\Local\\Temp\\", "\\INetCache\\", "\\WinSxS\\"))
    | summarize
        FileCount       = count(),
        DistinctFolders = dcount(FolderPath),
        SampleFiles     = make_set(FileName, 5),
        SampleFolders   = make_set(FolderPath, 5)
        by DeviceName,
           Account = InitiatingProcessAccountName,
           Process = InitiatingProcessFileName,
           ProcessCmd = InitiatingProcessCommandLine,
           TimeWindow = bin(TimeGenerated, TimeBin)
    | where FileCount >= FileBurstThreshold and DistinctFolders >= DistinctFolderThreshold
    | extend
        Signal = "🔴 Mass File Deletion",
        RiskScore = 9,
        Detail = substring(strcat(
            "Deleted: ", tostring(FileCount),
            " | Folders: ", tostring(DistinctFolders),
            " | Samples: ", tostring(SampleFiles)), 0, 400)
    | project TimeGenerated = TimeWindow, Signal, RiskScore, DeviceName,
              Account, Process, ProcessCmd, FileCount, DistinctFolders, Detail
)
| extend Severity = "🔴 Critical"
| project
    TimeGenerated,
    Severity,
    RiskScore,
    Signal,
    DeviceName,
    Account,
    Process,
    FileCount,
    DistinctFolders,
    Detail,
    ProcessCmd
| extend
    timestamp           = TimeGenerated,
    HostCustomEntity    = DeviceName,
    AccountCustomEntity = Account
| sort by RiskScore desc, FileCount desc
```

---

## 📚 Reference

MITRE ATT&CK: T1486 (Data Encrypted for Impact), T1485 (Data Destruction), T1490 (Inhibit System Recovery), T1489 (Service Stop), T1005 (Data from Local System).