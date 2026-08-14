# 🛡️ Detection Engineering & Threat Hunting

A curated library of KQL detection rules, threat hunting queries, and 
Sentinel/Defender workbooks built to detect real-world attacks in 
enterprise environments.

---

## 🎯 About

This repo contains detection engineering and threat hunting content 
developed for Microsoft Sentinel and Microsoft Defender XDR. Detections 
are mapped to MITRE ATT&CK and focused on threats actively targeting 
enterprise environments — including external tenant impersonation, 
identity attacks, EDR evasion, and living-off-the-land techniques.

---

## 🔍 What's Inside

### 🎯 Threat Hunting Queries
- Proactively hunt for potential malicious activities in the environment. 
  - **EDR Evasion & Defense Evasion** — BYOVD, ASR bypass, Defender tampering
  - **Identity Attacks** — Password spray, MFA fatigue, impossible travel, risky sign-ins
  - **Data Exfiltration** — Sensitive file downloads, mass OneDrive/SharePoint access
  - **Living-Off-the-Land** — PowerShell abuse, LOLBin misuse, obfuscated commands
  - **+ More**

### 📊 Workbooks & Dashboards
- **Endpoint Security Dashboard** — AV/ASR blocks, rare process executions, elevated PowerShell activity
- **Incident Response Dashboard** — Streamline Incident Response and view timelines in a holistic approach
- **Digital Forensics Dashboard** — Gather evidence in a unified dashboard 

### ⚡ Custom Detection Rules
- Production-ready analytics rules for Sentinel and Defender XDR covering high-fidelity detections with tuned false-positive rates.

---

## 🛠️ Tools & Platforms

- Microsoft Sentinel
- Microsoft Defender XDR (Endpoint, Identity, Office 365, Cloud Apps)
- KQL (Kusto Query Language)
- Azure Logic Apps
- PowerShell

---

## 📚 Standards & Conventions

- **MITRE ATT&CK mapping** on all detections
- **14-day lookback** as standard hunting window
- **False positive tuning** documented per detection
- **Severity scoring** based on confidence and impact

---

## ⚠️ Disclaimer

All queries are provided as-is for educational and defensive purposes. 
Content is sanitized and does not contain any organization-specific 
information. Test in a non-production environment before deploying.

---

## 📫 Connect

Feel free to reach out on [LinkedIn](https://www.linkedin.com/in/nguyentimmy/) for questions, feedback, or collaboration.
