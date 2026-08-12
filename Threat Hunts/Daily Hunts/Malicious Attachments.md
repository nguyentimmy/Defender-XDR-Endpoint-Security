# 📧 Malicious Email Attachments — Delivery & Click Status

**Matches inbound attachments against MalwareBazaar hashes, then answers the question that determines urgency: did it actually reach anyone, and did they click?**

---

## 🎯 Purpose

Knowing a malicious file was emailed to your org is only half the picture. A payload that got quarantined is a report; the same payload sitting in an inbox is an incident.

This hunt correlates attachment hashes against abuse.ch MalwareBazaar, then enriches every match with the **delivery outcome** and **whether the recipient clicked**. Severity is driven by real exposure rather than by the mere presence of a bad hash.

---

## 🚨 The key signal: exposure, not detection

| Exposure | Score | Meaning |
| --- | --- | --- |
| 🔴 **Delivered to Inbox** | 10 | Payload is in front of the user right now |
| 🔴 **Delivered** | 9 | Reached the mailbox |
| 🟡 **Junked** | 5 | Filtered, but still retrievable by the user |
| 🟢 **Blocked / Quarantined** | 2 | Controls worked |

**Plus 3 if the recipient clicked.** A click on a delivered payload is the highest-priority row in the output — that's user execution, not attempted delivery.

---

## 🔍 How it works

| Step | Logic |
| --- | --- |
| 1️⃣ | Pull recent SHA256 hashes from MalwareBazaar |
| 2️⃣ | Join against `EmailAttachmentInfo` on hash — broadcast strategy, since the feed is small |
| 3️⃣ | Join `EmailEvents` on `NetworkMessageId` for delivery action and location |
| 4️⃣ | Classify exposure level from delivery outcome |
| 5️⃣ | Left-join `UrlClickEvents` to detect recipient interaction |
| 6️⃣ | Score, dedupe, and rank by real risk |

The `NetworkMessageId` join is what makes this work — it's the key that ties an attachment record to its delivery outcome and any subsequent click.

---

## ⚠️ KQL

```
// ============================================================
// MALICIOUS EMAIL ATTACHMENTS - Delivery & Click Status
// ============================================================
// MITRE ATT&CK:
//   Tactic:    Initial Access, Execution
//   Technique: T1566.001 - Phishing: Spearphishing Attachment
//              T1204.002 - User Execution: Malicious File
// ============================================================
// Matches email attachments against abuse.ch MalwareBazaar hashes,.
// then enriches with delivery action (delivered/blocked/junked) and
// whether the URL/attachment was clicked — prioritizing real exposure.
// ============================================================
let LookbackTime = 7d;
// === MalwareBazaar - recent SHA256 hashes ===
let MalwareHashes = materialize(
    externaldata(Indicator:string)
    [@"https://bazaar.abuse.ch/export/txt/sha256/recent/"]
    with (format="txt")
    | where Indicator !startswith "#"
    | where Indicator matches regex @"^[A-Fa-f0-9]{64}$"
    | distinct Indicator
);
// === 1. Match malicious attachment hashes ===
let MaliciousAttachments =
EmailAttachmentInfo
| where Timestamp > ago(LookbackTime)
| where isnotempty(SHA256)
| join hint.strategy=broadcast kind=inner (MalwareHashes) on $left.SHA256 == $right.Indicator
| project AttachTime = Timestamp, SenderFromAddress, RecipientEmailAddress,
          FileName, FileType, SHA256, NetworkMessageId;
// === 2. Enrich with delivery outcome from EmailEvents ===
MaliciousAttachments
| join kind=inner (
    EmailEvents
    | where TimeGenerated > ago(LookbackTime)
    | project NetworkMessageId, Timestamp = TimeGenerated,
              Subject, EmailDirection,
              DeliveryAction, DeliveryLocation,
              ThreatTypes, Recipient = RecipientEmailAddress
) on NetworkMessageId
// --- Classify exposure level ---
| extend ExposureLevel = case(
    DeliveryLocation in ("Inbox/folder", "Inbox"), "🔴 DELIVERED TO INBOX",
    DeliveryAction == "Delivered", "🔴 DELIVERED",
    DeliveryLocation == "Junk", "🟡 Junked",
    DeliveryAction in ("Blocked", "Replaced"), "🟢 Blocked",
    DeliveryLocation == "Quarantine", "🟢 Quarantined",
    "⚪ Unknown"
)
// --- Risk Score based on exposure ---
| extend RiskScore = case(
    ExposureLevel == "🔴 DELIVERED TO INBOX", 10,
    ExposureLevel == "🔴 DELIVERED", 9,
    ExposureLevel == "🟡 Junked", 5,
    2
)
// --- Check if the recipient CLICKED a URL (highest risk) ---
| join kind=leftouter (
    UrlClickEvents
    | where TimeGenerated > ago(LookbackTime)
    | project NetworkMessageId, ClickTime = TimeGenerated,
              ClickedUrl = Url, ClickAction = ActionType
) on NetworkMessageId
| extend WasClicked = isnotempty(ClickTime)
| extend RiskScore = iff(WasClicked, RiskScore + 3, RiskScore)
| extend Severity = case(
    RiskScore >= 10, "🔴 Critical",
    RiskScore >= 7,  "🟠 High",
    RiskScore >= 4,  "🟡 Medium",
    "🟢 Low"
)
// --- Deduplicate ---
| summarize
    FirstSeen    = min(AttachTime),
    LastSeen     = max(AttachTime),
    WasClicked   = max(WasClicked)
    by Severity, RiskScore, ExposureLevel,
       SenderFromAddress, Recipient, Subject,
       FileName, FileType, SHA256,
       DeliveryAction, DeliveryLocation
| project
    FirstSeen,
    Severity,
    RiskScore,
    ExposureLevel,
    WasClicked,
    Recipient,
    SenderFromAddress,
    Subject,
    FileName,
    FileType,
    DeliveryAction,
    DeliveryLocation,
    SHA256
| extend timestamp = FirstSeen, AccountCustomEntity = Recipient
| sort by RiskScore desc, FirstSeen desc
```
## 📚 Reference

MITRE ATT&CK: T1566.001 (Spearphishing Attachment), T1204.002 (User Execution: Malicious File).

Feed: `https://bazaar.abuse.ch/export/txt/sha256/recent/`
