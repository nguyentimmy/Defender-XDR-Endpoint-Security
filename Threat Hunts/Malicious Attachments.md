
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