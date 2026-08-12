# 🔬 Digital Forensics Workbook

**Complete, unfiltered evidence collection for a single device within a narrow time window.**

Where the IR workbook detects and scopes, this one reconstructs. Set a device and a tight window, and every panel scopes to it simultaneously.

---

## 🎯 Purpose

Once the IR workbook or alert tells you *what* happened and *when*, this workbook shows you *everything* that occurred in that window — no suppression, no scoring, ordered chronologically.

The filtering difference is deliberate. IR hides benign activity so the timeline stays readable; forensics keeps it, because the "benign" rows are often what explain how the malicious ones connect. Carrying IR's exclusion lists here would delete the evidence.

---

## 📋 Panels

| # | Panel | Reconstructs |
| --- | --- | --- |
| 1 | 🌳 **Process Execution & Lineage** | Full ancestry — walk backward from a payload to the initial click |
| 2 | 📁 **File System Activity** | Creates, modifies, renames, deletes, plus download provenance |
| 3 | 🌐 **Network & DNS** | Every connection and query, with the initiating process |
| 4 | 👤 **Logon Sessions** | Attribution — which account was present when it happened |
| 5 | 🔧 **Persistence & Autoruns** | Autorun keys, tasks, services, startup folder, WMI, drivers |
| 6 | 📧 **Email Delivery & Click** | Initial access — patient zero |
| 7 | 🧬 **DLL / Image Loads** | Sideloading, unsigned modules from user-writable paths |
| 8 | 🗂️ **Registry Modifications** | What the attacker *changed* about the host |

---

## ⚙️ Parameters

| Parameter | Notes |
| --- | --- |
| `DeviceName` | Query-backed dropdown from `DeviceInfo` |
| `UserPrincipalName` | Required for Panel 6 — email tables have no device column |
| `TimeRange` | **Enable "Allow custom"** so analysts can set an exact window |

Panels are separate query steps sharing one parameter set, so you can scroll between them and correlate a process start against the file it wrote and the connection it opened at the same timestamps.

---

## 🧭 Usage

Start with a **one-to-two-hour window** around the event IR identified, and widen only as needed. These panels return everything — a multi-day window on a busy host will hit the row cap.

Sorted **ascending** throughout, because forensic timelines read forward.

Panels 5, 7, and 8 hide routine volume when no device is selected and show everything once you scope to one — `DeviceImageLoadEvents` and `DeviceRegistryEvents` log enormous amounts of normal activity, so fleet-wide they surface only anomalies.
