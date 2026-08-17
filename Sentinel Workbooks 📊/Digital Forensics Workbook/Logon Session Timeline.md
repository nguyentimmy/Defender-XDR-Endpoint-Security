# 🔑 Logon & Session Timeline

**Reconstructs the full authentication record for a device — who was on it, from where, and how they got in.**

---

## 🎯 Purpose

Every file drop, process launch, and network connection on an endpoint happened under *someone's* session. This is the attribution panel — the query that answers "who was on this box when it happened?"

When you're investigating a compromise, the file timeline tells you *what*, the process tree tells you *how*, but the logon record tells you *who*. And once you have the account, you have the pivot point into every user-side investigation that follows — sign-in logs in Entra, mailbox access, cloud resource activity, lateral movement to other endpoints.

This query pulls the full authentication history for a device, tags remote and external sessions, and preserves the source information needed to trace the session back to its origin.

---

## 🔍 How it works

| Step | Logic |
| --- | --- |
| 1️⃣ | Filter `DeviceLogonEvents` to the target device and time window |
| 2️⃣ | Tag `IsRemote` for `RemoteInteractive`, `Network`, and `NetworkCleartext` logons |
| 3️⃣ | Tag `IsRdp` specifically for `RemoteInteractive` — the interactive attacker session |
| 4️⃣ | Tag `FromExternalIP` when `RemoteIPType == "Public"` |
| 5️⃣ | Coalesce `Source` from `RemoteIP → RemoteDeviceName → "local"` for readable attribution |
| 6️⃣ | Project the full session record with account, protocol, and process context |
| 7️⃣ | Sort ascending — session sequence reads top to bottom |

---

## ⚖️ Risk signals surfaced

- **RDP from public IP** — `IsRdp = YES` + `FromExternalIP = YES` is the exposed-RDP compromise pattern
- **`NetworkCleartext` logon** — credentials transmitted in the clear, almost always a misconfiguration or attack tooling
- **`LocalAdmin = True` from remote source** — privileged remote session, worth scrutinizing every time
- **Repeated failures then success** — password spray or brute force that eventually landed
- **Unusual `InitiatingProcessFileName`** — logons initiated by `psexec.exe`, `wmic.exe`, `wmiprvse.exe`, or PowerShell suggest lateral movement tooling
- **`RemoteDeviceName` you don't recognize** — pivot the other direction and investigate that host

---

## 🔍 KQL

```kql
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
---

## 📚 Reference

MITRE ATT&CK: T1078 (Valid Accounts), T1021.001 (Remote Services: Remote Desktop Protocol), T1021.002 (SMB/Windows Admin Shares), T1110 (Brute Force), T1550 (Use Alternate Authentication Material).

**Parameters:** `{DeviceName}` (leave empty to run across all devices), `{TimeRange}` (e.g., `between (datetime(2026-08-13) .. datetime(2026-08-14))` or `> ago(24h)`).