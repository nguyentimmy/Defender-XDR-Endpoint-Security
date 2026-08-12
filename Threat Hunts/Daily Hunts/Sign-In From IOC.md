# 🚪 Successful Sign-Ins from Known Malicious IPs

**Correlates successful Entra ID authentications against known-malicious IP infrastructure — a high-fidelity account-compromise signal.**

---

## 🎯 Purpose

Failed sign-ins from bad IPs are background noise; the internet is constantly spraying credentials at every tenant. A **successful** sign-in from an IP that appears on a botnet C2 list or an attacking-IP feed is a different thing entirely.

It means valid credentials worked from infrastructure with a known malicious history. That's not a suspicious pattern requiring interpretation — it's an account that needs attention now.

The query filters to `ResultType == 0` for exactly this reason. Precision over volume.

---

## 🌐 Multi-feed enrichment

Native Sentinel Threat Intel is a good baseline but reflects only what your own connectors ingest. This hunt widens visibility by unioning external open-source feeds alongside it, so an IP flagged by the broader community surfaces even if your TI connectors haven't picked it up.

| Feed | Coverage |
| --- | --- |
| **Sentinel TI** | Your own curated and connector-supplied indicators |
| **abuse.ch Feodo Tracker** | Active botnet command-and-control infrastructure |
| **blocklist.de** | IPs observed attacking services (SSH, mail, web) |

`FeedSources` is carried through to the output as a set, so each row shows **which** feeds flagged the IP. That drives triage confidence directly: a Feodo C2 match means the source is live botnet infrastructure, while a blocklist.de match alone is broader and warrants a second look before escalation.

Feeds are combined by IP with `make_set`, so an address appearing on multiple lists shows all of them.

---

## 🔍 How it works

| Step | Logic |
| --- | --- |
| 1️⃣ | Pull active IP indicators from `ThreatIntelligenceIndicator` |
| 2️⃣ | Fetch Feodo Tracker and blocklist.de via `externaldata` |
| 3️⃣ | Union all three, grouping feed sources per IP |
| 4️⃣ | Filter `SigninLogs` to **successful** authentications only |
| 5️⃣ | Inner-join on IP address |
| 6️⃣ | Score by Entra ID risk level and Conditional Access outcome |

---

## ⚖️ Severity

| Condition | Level |
| --- | --- |
| Entra ID risk level high or medium | 🔴 Critical |
| Successful sign-in from a flagged IP | 🟠 High |

Entra ID's own risk assessment agreeing with the feed match is the strongest combination — two independent systems reaching the same conclusion about the same authentication.

---

## 🔍 KQL

```
// ============================================================
// SUCCESSFUL SIGN-INS FROM KNOWN MALICIOUS IPs
// ============================================================
// MITRE ATT&CK:
//   Tactic:    Initial Access, Credential Access
//   Technique: T1078 - Valid Accounts
//              T1078.004 - Valid Accounts: Cloud Accounts
// ============================================================
// Correlates successful Entra ID sign-ins against known-malicious IPs
// from Sentinel Threat Intel + abuse.ch (Feodo C2, blocklist.de) —
// a high-fidelity account-compromise signal with minimal false positives.
// ============================================================

let LookbackTime = 14d;
// === Sentinel Threat Intel IPs ===
let TI_IPs = ThreatIntelligenceIndicator
    | where TimeGenerated > ago(30d)
    | where Active == true
    | where isnotempty(NetworkIP)
    | distinct NetworkIP;
// === abuse.ch Feodo Tracker - Botnet C2 IPs ===
let Feodo_IPs = materialize(
    externaldata(Indicator:string)
    [@"https://feodotracker.abuse.ch/downloads/ipblocklist.txt"]
    with (format="txt")
    | where Indicator matches regex @"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    | distinct Indicator
);
// === blocklist.de - Known attacking IPs ===
let Blocklist_IPs = materialize(
    externaldata(Indicator:string)
    [@"https://lists.blocklist.de/lists/all.txt"]
    with (format="txt")
    | where Indicator matches regex @"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    | distinct Indicator
);
// === Combine all malicious IPs ===
let MaliciousIPs = materialize(
    union
        (TI_IPs | project MalIP = NetworkIP, FeedSource = "Sentinel TI"),
        (Feodo_IPs | project MalIP = Indicator, FeedSource = "Feodo C2"),
        (Blocklist_IPs | project MalIP = Indicator, FeedSource = "Blocklist.de")
    | summarize FeedSource = make_set(FeedSource) by MalIP
);
// === Correlate against successful sign-ins ===
SigninLogs
| where TimeGenerated > ago(LookbackTime)
| where ResultType == 0                        // successful sign-ins only
| project TimeGenerated, UserPrincipalName, IPAddress,
          AppDisplayName, ClientAppUsed,
          Country = tostring(LocationDetails.countryOrRegion),
          City = tostring(LocationDetails.city),
          RiskLevelDuringSignIn, ConditionalAccessStatus, UserAgent
| join kind=inner (MaliciousIPs) on $left.IPAddress == $right.MalIP
| extend Severity = case(
    RiskLevelDuringSignIn in ("high", "medium"), "🔴 Critical",
    ConditionalAccessStatus == "success", "🟠 High",
    "🟠 High"
)
| summarize
    FirstSeen     = min(TimeGenerated),
    LastSeen      = max(TimeGenerated),
    SignInCount   = count(),
    Apps          = make_set(AppDisplayName, 10),
    Countries     = make_set(Country, 5),
    FeedSources   = take_any(FeedSource)
    by UserPrincipalName, IPAddress, Severity, RiskLevelDuringSignIn
| project
    FirstSeen,
    LastSeen,
    Severity,
    UserPrincipalName,
    MaliciousIP = IPAddress,
    FeedSources,
    SignInCount,
    Apps,
    Countries,
    RiskLevelDuringSignIn
| extend timestamp = LastSeen, AccountCustomEntity = UserPrincipalName, IPCustomEntity = MaliciousIP
| sort by Severity asc, LastSeen desc
```

## 📚 Reference

MITRE ATT&CK: T1078 (Valid Accounts), T1078.004 (Valid Accounts: Cloud Accounts).

Feeds: `feodotracker.abuse.ch/downloads/ipblocklist.txt`, `lists.blocklist.de/lists/all.txt`
