# 🗝️ Registry Modification Timeline

**Every registry write in the window, categorized by security purpose — what the attacker *changed* about the host, separate from what they ran.**

---

## 🎯 Purpose

Process and file timelines answer what got executed and what got dropped. Registry writes answer a different question: what did the attacker *change* about the host? Defender exclusions, disabled real-time protection, WDigest re-enabled for credential caching, RDP turned on, UAC weakened, PowerShell logging suppressed — these are the changes that outlive the incident and dictate remediation scope.

This query is broader than the autoruns inventory. It surfaces every registry write, tags each one with a security purpose, and color-codes by severity so the highest-impact changes stand out at a glance.

---

## 🔍 How it works

| Step | Logic |
| --- | --- |
| 1️⃣ | Pull `DeviceRegistryEvents` for the target device and time window |
| 2️⃣ | Tag `Purpose` via a `case()` covering Defender tampering, credential exposure, remote access, UAC, persistence, PowerShell policy, boot/recovery, and proxy config |
| 3️⃣ | Color-code severity: 🔴 critical tampering, 🟠 high-impact change, 🟡 configuration, ⚪ everything else |
| 4️⃣ | Tag `IsSecuritySignificant` when purpose isn't `⚪ Other Registry Write` |
| 5️⃣ | Fleet-wide: keep only security-relevant writes. Device-scoped: keep everything for context |
| 6️⃣ | Project current and previous values so the diff is visible in one row |
| 7️⃣ | Sort ascending — modification sequence reads top to bottom |

---

## ⚖️ Risk signals surfaced

- **🔴 Defender Exclusion added** — attacker whitelisting their payload directory or extension before dropping it
- **🔴 Defender Protection Change** — real-time monitoring disabled, tamper protection bypassed
- **🔴 WDigest Credential Caching enabled** — `UseLogonCredential = 1` forces plaintext credentials into memory for `mimikatz`
- **🔴 LSA / SAM Modification** — direct tampering with the credential store, often precedes credential theft
- **🔴 Boot / Recovery Change** — SafeBoot config, SFC disabled — attacker preparing for reboot survival or blocking recovery
- **🟠 UAC / Token Policy weakened** — `EnableLUA = 0` or `LocalAccountTokenFilterPolicy = 1` disables privilege prompts
- **🟠 RDP enabled** — `fDenyTSConnections = 0` opens remote access
- **🟠 PowerShell Policy change** — script block logging or transcription disabled to hide activity
- **🟠 Proxy Configuration** — attacker routing traffic through their own infrastructure for interception or C2
- **`PreviousData` populated with a stronger value** — the diff itself is the story; check what the setting *used to be*

---

## 🔍 KQL

```kql
// ============================================================
// FORENSICS: Registry Modification Timeline
// ============================================================
// All registry writes in the window - broader than the autoruns inventory.
// Documents what the attacker CHANGED about the host, which is a separate
// question from what they ran, and is what remediation scoping needs.
// PARAMETERS: {DeviceName}, {TimeRange}
// ============================================================
let TargetDevice = "{DeviceName}";
DeviceRegistryEvents
| where TimeGenerated {TimeRange}
| where isempty(TargetDevice) or DeviceName has TargetDevice
| extend Purpose = case(
    // --- Security control tampering ---
    RegistryKey has_any ("Windows Defender\\Exclusions", "Microsoft\\Windows Defender\\Exclusions"),
        "🔴 Defender Exclusion",
    RegistryKey has_any ("Windows Defender\\Real-Time Protection", "DisableAntiSpyware",
        "DisableRealtimeMonitoring", "Windows Defender\\Features"),
        "🔴 Defender Protection Change",
    RegistryKey has "Policies\\Microsoft\\Windows Defender",
        "🔴 Defender Policy Change",
    // --- Credential exposure ---
    RegistryKey has_any ("SecurityProviders\\WDigest", "UseLogonCredential"),
        "🔴 WDigest Credential Caching",
    RegistryKey has_any ("Lsa\\", "SAM\\", "SECURITY\\Policy"),
        "🔴 LSA / SAM Modification",
    // --- Remote access enablement ---
    RegistryKey has_any ("Terminal Server\\fDenyTSConnections", "Terminal Server\\WinStations",
        "Control\\Terminal Server"),
        "🟠 RDP Configuration",
    RegistryKey has_any ("SharedAccess\\Parameters\\FirewallPolicy", "WindowsFirewall"),
        "🟠 Firewall Change",
    // --- Privilege / UAC ---
    RegistryKey has_any ("Policies\\System\\EnableLUA", "Policies\\System\\ConsentPrompt",
        "Policies\\System\\FilterAdministratorToken", "LocalAccountTokenFilterPolicy"),
        "🟠 UAC / Token Policy",
    // --- Persistence ---
    RegistryKey has_any ("CurrentVersion\\Run", "CurrentVersion\\RunOnce",
        "Winlogon\\Shell", "Winlogon\\Userinit", "Winlogon\\Notify",
        "Image File Execution Options", "AppInit_DLLs", "AppCertDlls"),
        "🟠 Autorun / Persistence",
    RegistryKey has "CurrentControlSet\\Services",
        "🟡 Service Configuration",
    // --- Execution / script policy ---
    RegistryKey has_any ("PowerShell\\1\\ShellIds", "ExecutionPolicy",
        "ScriptBlockLogging", "ModuleLogging", "Transcription"),
        "🟠 PowerShell Policy",
    // --- Boot / recovery ---
    RegistryKey has_any ("SafeBoot", "BootExecute", "Winlogon\\SfcDisable"),
        "🔴 Boot / Recovery Change",
    // --- Proxy / network redirection ---
    RegistryKey has_any ("Internet Settings\\ProxyServer", "Internet Settings\\ProxyEnable",
        "Internet Settings\\AutoConfigURL"),
        "🟠 Proxy Configuration",
    // --- Everything else ---
    "⚪ Other Registry Write"
)
| extend IsSecuritySignificant = iff(Purpose != "⚪ Other Registry Write", "YES", "")
// Fleet-wide, show only security-relevant writes; scoped to a device, show all
| where IsSecuritySignificant == "YES" or isnotempty(TargetDevice)
| project
    TimeGenerated,
    DeviceName,
    Purpose,
    Action = ActionType,
    RegistryKey,
    ValueName = RegistryValueName,
    ValueData = substring(coalesce(RegistryValueData, ""), 0, 250),
    ValueType = RegistryValueType,
    PreviousData = substring(coalesce(PreviousRegistryValueData, ""), 0, 150),
    Account = InitiatingProcessAccountName,
    ByProcess = InitiatingProcessFileName,
    ByProcessCmd = InitiatingProcessCommandLine,
    SHA256 = InitiatingProcessSHA256
| sort by TimeGenerated asc
```

---

## 📚 Reference

MITRE ATT&CK: T1112 (Modify Registry), T1562.001 (Impair Defenses: Disable or Modify Tools), T1562.002 (Disable Windows Event Logging), T1562.004 (Disable or Modify System Firewall), T1547.001 (Registry Run Keys / Startup Folder), T1546.012 (IFEO Injection), T1548.002 (Bypass User Account Control), T1003.001 (LSASS Memory), T1021.001 (Remote Desktop Protocol), T1090 (Proxy).