
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