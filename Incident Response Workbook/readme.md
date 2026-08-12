# Incident Response Workbook

Parameterized Microsoft Sentinel / Defender XDR queries for post-compromise investigation. Pick an entity and a time range, get a chronological timeline — no query editing.

| File | Scope | Answers |
| --- | --- | --- |
| `Device Compromise Triage.md` | One endpoint | What did the attacker do on this host? |
| `User Compromise Triage.md` | One account | What happened to this identity and mailbox? |
| `Data Exfil.md` | Fleet-wide or scoped | Did data leave? |

---

## Device Compromise Triage

Ten detection categories unioned into one timeline: persistence, credential access, defense evasion, ransomware prep, categorized recon, lateral movement, network egress, backdoor shells, unauthorized remote tools, and native Defender detections.

Every row carries the initiating process, command line, child process, and hash for immediate IOC extraction.

**Parameters:** `DeviceName`, `TimeRange`

---

## User Compromise Triage

Eight identity and mailbox signals: new MFA methods, MFA removal and password resets, forwarding and inbox rules, risky sign-ins, rare-country logons, malicious-IP logons, OAuth consent grants, and mailbox export.

**Parameters:** `UserPrincipalName`, `TimeRange`

---

## Data Exfil

Eight exfiltration channels, since data theft is a sequence rather than one event: file-sharing and paste-site uploads, exfil tooling (`rclone`, `megacmd`, `azcopy`, WinSCP), mass archiving, removable media, bulk cloud download, outbound attachments, forwarding rules, and connection fan-out.

**Parameters:** `DeviceName` (optional), `UserPrincipalName` (optional), `TimeRange` — leave both entity parameters empty for a fleet-wide sweep.

---

## Workflow

The three pivot into each other. Most intrusions cross both the endpoint and identity planes:

1. A device or account surfaces in an alert or on the endpoint dashboard
2. Triage that entity — the timeline names the other one
3. Run Data Exfil to determine whether anything was taken

---

## Notes

- Signals are grouped by technique, not by table, so results read as attacker activity. `Signal` is the triage axis.
- Weak indicators (execution-policy switches, temp paths, generic recon) add context but never fire alone.
- Known-benign parents are suppressed, but credential dumping, ransomware prep, backdoor shells, and defense evasion always surface regardless.
- Exclusion lists are environment-specific — populate internal domains, sanctioned tooling, and management paths before deploying.
- MITRE ATT&CK mappings are in each query header.

These are investigation aids, not detection rules. Pair the high-fidelity techniques with scheduled analytics rules for anything that should page someone.