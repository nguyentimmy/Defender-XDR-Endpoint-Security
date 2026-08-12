# 🔍 Incident Response Workbook

**On-demand post-compromise investigation for a single device or user account.**

Streamlines unified events across device and user compromise into one chronological timeline. Pick an entity, pick a time range, no query editing.

---

## 🎯 Purpose

Investigating one suspect entity traditionally means opening a dozen separate queries across process, registry, network, identity, and mailbox telemetry — then lining up timestamps by hand. During an active incident that setup work is the bottleneck, not the analysis.

This collapses it into two parameterized views. It answers **is something wrong, what kind, and when** — which is exactly what the Digital Forensics workbook needs as input.

---

## 🖥️ Device Tab

| Category | Signals |
| --- | --- |
| **Persistence** | Run keys, Winlogon, scheduled tasks, services, startup folder |
| **Credential Access** | LSASS dumping, Mimikatz, procdump, comsvcs, nanodump, pypykatz |
| **Defense Evasion** | Defender tampering, log clearing, auditpol, AMSI/ETW bypass |
| **Ransomware Prep** | Shadow copy deletion, recovery sabotage, backup destruction |
| **Discovery** | AD enumeration, BloodHound, Kerberos/SPN, cloud & host recon |
| **Lateral Movement** | PsExec, WMI, PowerShell remoting, admin shares |
| **Network Egress** | LOLBins reaching external infrastructure |
| **Backdoor Shells** | Reverse shells, named pipes, web shells |
| **Remote Access** | Unauthorized RATs and tunneling tools |
| **Defender Detections** | Native AV, ASR, Exploit Guard hits |
| **Local Accounts** | Account creation, privileged group additions |

Every row carries the initiating process, its command line, the spawned child process, and the file hash for immediate IOC extraction.

---

## 👤 User Tab

| Category | Signals |
| --- | --- |
| **MFA Changes** | New authentication methods registered |
| **Account Takeover** | MFA removed, password resets, device unregistration |
| **Mailbox Rules** | Forwarding, redirect, and inbox rule creation |
| **Risky Sign-ins** | Entra ID risk detections and anomalous logons |
| **Rare Geography** | Sign-ins from countries unusual for this specific user |
| **Malicious IPs** | Logons correlated against threat-intel feeds |
| **OAuth Consent** | App permission grants used for persistence |
| **Mailbox Export** | eDiscovery and bulk mail export |

---

## 🔄 Pivoting

**The two tabs are designed to pivot into each other.** Most intrusions cross both the endpoint and identity planes:

- A risky sign-in names a device → open the device tab
- A compromised endpoint names a logged-in account → open the user tab

Start with whichever entity you have and follow the trail to the other.

---

## ⚙️ Parameters

| Parameter | Notes |
| --- | --- |
| `DeviceName` | Query-backed dropdown from `DeviceInfo` |
| `UserPrincipalName` | Query-backed dropdown from `SigninLogs` |
| `TimeRange` | Binds to `TimeGenerated` |

Query-backed rather than free text — a typo returns an empty result set that looks identical to a clean entity.

---

## 🧠 Design notes

**Grouped by technique, not by table.** The timeline reads as attacker activity rather than raw telemetry, with `Signal` as the triage axis.

**Weak indicators can't fire alone.** Execution-policy switches, temp paths, hidden windows, and generic recon are used by nearly every legitimate automation tool. They add context to a row that already matched something meaningful.

**Suppression has a hard-signal bypass.** Known-benign parents are filtered post-union to keep the timeline readable, but credential dumping, ransomware prep, backdoor shells, and defense evasion **always surface** — a binary masquerading as a trusted agent still appears.

**Fingerprint, don't allowlist by name.** Every exclusion pins both a command-line shape *and* its parent process or path. Allowlisting a filename alone creates a blind spot malware can occupy by adopting that name.

**Schema pinned across the union.** An empty `datatable` with the explicit output schema keeps column order stable when a section returns no rows. Declare numeric columns `long`, not `int` — KQL integer literals are `long`, and a mismatch silently splits the column.
