# 🛡️ Sentinel Workbook Suite — How These Fit Together

Three Microsoft Sentinel / Defender XDR workbooks. They are not alternatives to each other — they're sequential stages of the same investigation, and each one hands off to the next.

---

## 🗺️ The three at a glance

| Workbook | Mode | Question it answers | Scope |
| --- | --- | --- | --- |
| 📊 **Endpoint Security** | Continuous monitoring | *Is anything wrong across the fleet?* | All devices |
| 🔍 **Incident Response** | On-demand, parameterized | *What happened to this device or user?* | One entity |
| 🔬 **Digital Forensics** | On-demand, narrow window | *Reconstruct exactly what occurred* | One entity, minutes to hours |

---

## 🔄 The workflow

```
📊 Endpoint Security Workbook
   Fleet-wide monitoring — something surfaces
              ↓  gives you an entity
🔍 Incident Response Workbook
   Unified device + user timeline — confirms and scopes
              ↓  gives you a device AND a timestamp
🔬 Digital Forensics Workbook
   Complete unfiltered evidence in that window
```

The dependency runs one direction. **You can't start with forensics**, because forensics needs a narrow time window to be usable — and you don't know the window until IR tells you when the activity happened.

---

## 📊 Endpoint Security Workbook

**Purpose: continuous endpoint monitoring.**

This is the one you glance at. It watches the fleet for prevention hits, evasion attempts, unsanctioned tooling, and telemetry gaps — activity that isn't tied to a specific open investigation.

Panels cover unapproved remote-access tools, rare service processes, EDR evasion attempts, ASR blocks, antivirus detections, and Defender sensor health.

It's the layer that tells you *where to look*. When a device shows up here repeatedly, or an AV detection comes back unremediated, that device becomes the input to the IR workbook.

> 💡 The Defender Health panel belongs first — it shows which devices aren't reporting telemetry, which determines how much you can trust every other panel.

---

## 🔍 Incident Response Workbook

**Purpose: streamline unified events across device and user compromise.**

This is the core of the suite. Pick a device or an account, pick a time range, and get a single chronological timeline of post-compromise activity — no query editing, no jumping between tabs.

Without it, investigating one suspect entity means opening a dozen separate queries across process, registry, network, identity, and mailbox telemetry, then lining up timestamps by hand. During an active incident that setup work is the bottleneck, not the analysis. This collapses it into one view.

**Device tab** — persistence, credential access, defense evasion, ransomware prep, categorized recon, lateral movement, network egress, backdoor shells, unauthorized remote tools, Defender detections.

**User tab** — MFA registration and removal, password resets, mailbox forwarding rules, risky sign-ins, rare-country and malicious-IP logons, OAuth consent grants, mailbox export.

Results are **filtered and scored**. Known-benign activity is suppressed so the timeline stays readable, while high-fidelity signals — credential dumping, ransomware prep, backdoor shells, defense evasion — always surface regardless of suppression.

> 💡 **The two tabs pivot into each other.** Most intrusions cross both the endpoint and the identity plane. A risky sign-in names a device; a compromised endpoint names a logged-in account. Start with whichever entity you have and follow the trail to the other.

---

## 🔬 Digital Forensics Workbook

**Purpose: deeper analysis of the events IR surfaced.**

Once IR tells you *what* happened and *when*, this workbook reconstructs it completely. Set the same device and a tight window around the activity, and every panel scopes to it simultaneously.

Panels cover process execution and lineage, file system activity, network and DNS, logon sessions, and persistence and autoruns inventory.

The critical difference: **this workbook does not filter.** Where IR suppresses benign activity to stay readable, forensics shows everything in the window. That's deliberate — you're reconstructing a sequence, and the "benign" rows are often what explain how the malicious ones connect. Filtering here would delete the evidence.

Panels are separate steps sharing one parameter set, so you can read across them and correlate a process start against the file it wrote and the connection it opened at the same timestamps.

> 💡 Start with a one-to-two-hour window around the event and widen only as needed. These panels return everything — a multi-day window on a busy host will hit the row cap.

---

## ⚖️ Filtered vs. unfiltered — why it matters

The single most important distinction between IR and Forensics:

| | Incident Response | Digital Forensics |
| --- | --- | --- |
| Suppression | Benign parents filtered | None |
| Scoring | Signals classified and ranked | Chronological, unranked |
| Result size | Dozens of rows | Hundreds to thousands |
| Time window | 24 hours to 7 days | Minutes to hours |
| Purpose | Detect and scope | Reconstruct and document |

Both approaches are correct for their stage. Carrying IR's exclusion lists into forensics would remove the very rows that explain the sequence; carrying forensics' completeness into IR would bury the signals under normal system activity.

---

## 🧭 Quick reference — which one do I open?

| Situation | Workbook |
| --- | --- |
| Morning check, nothing specific | 📊 Endpoint Security |
| An alert fired on a device | 🔍 Incident Response |
| A user reported a phishing email | 🔍 Incident Response (user tab) |
| IR showed credential dumping at 14:22 | 🔬 Digital Forensics, scoped 14:00–14:45 |
| Writing the incident report timeline | 🔬 Digital Forensics |
| Checking whether protection is disabled anywhere | 📊 Endpoint Security |

---

## 📌 Notes

Exclusion lists across all three are environment-specific and appear as placeholders. Populate internal domains, sanctioned tooling, management paths, and known-benign agents before deploying.

These are monitoring and investigation aids, not detection rules — they surface activity for human review. Pair the high-fidelity techniques with scheduled analytics rules for anything that should page someone.
