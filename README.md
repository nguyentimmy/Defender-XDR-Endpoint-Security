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
- **EDR Evasion & Defense Evasion** — BYOVD, ASR bypass, Defender tampering
- **Identity Attacks** — Password spray, MFA fatigue, impossible travel, risky sign-ins
- **Social Engineering** — Storm-1811 patterns, external tenant impersonation, Quick Assist abuse
- **Data Exfiltration** — Sensitive file downloads, mass OneDrive/SharePoint access
- **Cryptomining** — Stratum protocol connections, mining pool infrastructure, miner binaries
- **Supply Chain** — Malicious npm/PyPI packages, IPFS-based payload delivery
- **Living-Off-the-Land** — PowerShell abuse, LOLBin misuse, obfuscated commands
- **+ More To Come**

### 📊 Workbooks & Dashboards
- **Endpoint Security Dashboard** — AV/ASR blocks, rare process executions, elevated PowerShell activity
- **Email Threat Overview** — Phishing trends, quarantine analysis, external sender patterns
- **Identity Risk Dashboard** — Risky sign-ins, MFA anomalies, service principal activity

### ⚡ Custom Detection Rules
Production-ready analytics rules for Sentinel and Defender XDR covering 
high-fidelity detections with tuned false-positive rates.


---

## 🗺️ MITRE ATT&CK Coverage

Detections are mapped to MITRE ATT&CK tactics including:

- **Initial Access** (T1566, T1078)
- **Execution** (T1059, T1204)
- **Persistence** (T1547, T1543)
- **Defense Evasion** (T1562, T1027, T1218)
- **Credential Access** (T1110, T1003, T1621)
- **Discovery** (T1018, T1082, T1482)
- **Collection** (T1005, T1560)
- **Command and Control** (T1071, T1105)
- **Exfiltration** (T1041, T1567)
- **Impact** (T1486, T1496)

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

Feel free to reach out on [LinkedIn](https://www.linkedin.com/in/nguyentimmy/) 
for questions, feedback, or collaboration.
