## 📊 Endpoint Security Workbook

Continuous fleet-wide endpoint monitoring. The layer that tells you where to look.
Panels spanning prevention, detection, evasion, and visibility — designed to be glanced at rather than queried.

🎯 Purpose

This workbook watches the whole estate for activity that isn't tied to an open investigation: prevention hits, evasion attempts, unsanctioned tooling, and telemetry gaps.

It's the front of the funnel. When a device shows up here repeatedly — or an antivirus detection comes back unremediated — that device becomes the input to the Incident Response workbook.
---

## 🖥️ Unapproved Remote Tools

**Detects remote-access software that isn't sanctioned tooling.**

RMM agents, remote-support clients, and VNC variants executing on endpoints — the primary delivery mechanism for vishing and helpdesk-impersonation attacks, where a caller convinces a user to install a remote tool and hands over the session.

- Flags scam-favored tools separately from general RMM (`IsHighAbuseTool`)
- Weights execution from user-writable paths, since attackers run portable builds rather than installing
- `IsPortableExec` catches tools running outside `Program Files`
- Approved internal tooling is excluded, so only *unauthorized* use surfaces

**Severity:** high-abuse tool + suspicious path = Critical. Either signal alone = High.

---

## ⚙️ Rare Process as Service

**Surfaces uncommon child processes of `services.exe`.**

Service creation is a durable persistence method that survives reboots and runs as SYSTEM. This panel baselines what normally spawns from the service host and flags the outliers — processes appearing fewer than six times per device and absent from a known-good watchlist.

- Enriched with network connections, file modifications, and DLL loads per process
- Severity weights execution from user-writable paths plus external network egress
- Requires a populated `KnownProcesses` watchlist to be meaningful

**Severity:** suspicious path + external network = High. Either alone = Medium.

---

## 🥷 EDR Evasions

**Detects attempts to blind or disable security tooling.**

Attackers routinely neutralize endpoint protection before the damaging phase. This panel covers seven techniques in one view.

- **BYOVD** — known-vulnerable signed drivers loaded or dropped to disk
- **EDR-killer tools** — AuKill, Terminator, EDRKillShifter, EDRSilencer, and similar
- **Process/service termination** — killing or disabling EDR agents and services
- **Defender tampering** — protection disabled, or exclusions added
- **Safe Mode abuse** — booting without EDR drivers loaded
- **Event log / ETW tampering** — destroying or suppressing telemetry
- **Native tamper events** — Defender's own tampering signals

**Severity:** most techniques score Critical; Defender *exclusions* score High, since they have legitimate administrative uses.

---

## 🛡️ ASR Detections

**Attack Surface Reduction rule blocks, ranked by rule impact.**

ASR is prevention rather than detection — a hit means something was stopped. The value is in *which* rule fired, since that indicates what the attacker was attempting.

- Severity assigned per rule rather than uniformly: ransomware, email-executable, Office-child-process, and vulnerable-driver blocks rank highest
- Injection, obfuscated-script, and untrusted-executable blocks rank medium
- Environment-specific noisy rules and known-good processes are excluded

**Reading it:** a spike in Office-child-process blocks on one device is a phishing attempt landing; a vulnerable-driver block is likely BYOVD in progress.

---

## 🦠 AV Detections

**Defender antivirus detections weighted by remediation outcome.**

A detection isn't automatically a resolved detection. This panel separates threats that were actually cleaned from those that were detected but left in place.

- `NotRemediated` — detected but remediation failed, was allowed, or didn't complete
- `WasRunning` — the threat was executing at detection time
- `IsHighImpactFamily` — ransomware, backdoors, RATs, credential-theft tooling, loaders
- Execution from user-writable paths adds weight

**The row that matters:** a high-impact family that was **running** and **not remediated** is a live infection, not a caught one — that's the trigger to pivot into device triage.

---

## 💓 Defender Health

**The blind-spot map: onboarded devices whose sensor isn't reporting healthy.**

Every other panel on this dashboard depends on telemetry arriving. A device with an inactive or misconfigured sensor generates no detections — which looks identical to a clean device. This panel closes that gap.

- Filters to devices marked Onboarded whose `SensorHealthState` isn't Active
- Severity: Inactive or Misconfigured = Critical; ImpairedCommunication = High

**Note:** an empty result is the healthy state — it means every onboarded device is reporting.

**Placement:** worth putting first on the dashboard, since it tells you how much to trust everything below it.

---

## Known limitation

Secure-configuration posture — real-time protection off, tamper protection disabled, stale signatures — lives in the `DeviceTvm*` tables, which are **Defender XDR only** and are not streamed to Log Analytics by the standard connector. Those queries return no results in a Sentinel workbook even though they work in Advanced Hunting.

| Works in a Sentinel workbook | Advanced Hunting only |
| --- | --- |
| `DeviceInfo`, `DeviceEvents`, `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`, `DeviceImageLoadEvents` | All `DeviceTvm*` tables |

The Defender Health panel uses `DeviceInfo` for this reason — it covers the most important blind spot (sensors not reporting) and works in both backends. Run configuration-posture queries Defender-side.

---

## Notes

Exclusion lists in each panel are environment-specific and appear as placeholders in the published queries. Populate them with your own sanctioned tooling, management agents, and confirmed-benign processes before deploying.

Panels are tuned for monitoring, not alerting. Pair the high-fidelity techniques — EDR tampering, unremediated high-impact detections — with scheduled analytics rules for anything that warrants paging someone.
