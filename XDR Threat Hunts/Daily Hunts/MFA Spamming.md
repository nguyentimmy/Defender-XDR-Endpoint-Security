# 🔔 MFA Fatigue / Push Bombing Detection

**Detects MFA push-bombing campaigns, flags when the user caved, and enriches the source IP against multiple threat-intel feeds.**

---

## 🎯 Purpose

MFA fatigue works by wearing the target down. An attacker who already has valid credentials fires authentication prompt after authentication prompt until the user approves one out of confusion, annoyance, or by reflex at 2am.

The attack is noisy by nature — dozens of denials in minutes — which makes it detectable. This hunt finds the bombing pattern, then answers the question that actually determines severity: **did it work?**

---

## 🚨 The key signal: `UserCaved`

Most MFA-spam detections stop at "someone got a lot of prompts." That's the wrong place to stop.

If the burst of denials **ends in a success**, the attacker is inside. `SuccessfulAttempts > 0` inside a bombing window isn't a suspicious pattern — it's a confirmed compromise, and the response is session revocation, not a user awareness email.

| Outcome | Meaning |
| --- | --- |
| Denials only | ⚠️ Attempted — credentials are already known, rotate them |
| Denials **then success** | 🔴 Compromised — the attacker holds a valid session |

---

## 🔍 Detection logic

| Step | Logic |
| --- | --- |
| 1️⃣ | Filter `SigninLogs` to MFA-required authentications |
| 2️⃣ | `mv-expand` `AuthenticationDetails` to reach per-step results |
| 3️⃣ | Count denial types: declined, no response, duplicate attempt |
| 4️⃣ | Aggregate per user **and** source IP |
| 5️⃣ | Flag when ≥5 denials land inside a 10-minute window |
| 6️⃣ | Check whether any attempt succeeded → `UserCaved` |
| 7️⃣ | Enrich the source IP against threat-intel feeds |

Tunable: `SpamWindow` (10m) and `MinFailedAttempts` (5).

---

## 🌐 Feed enrichment

Four feeds, weighted by what each implies. These are **severity boosters, not gatekeepers** — the bombing pattern alone is enough to surface a row, since attackers frequently spam from clean residential proxies that appear on no list.

| Feed | Weight | Meaning |
| --- | --- | --- |
| **Feodo Tracker** | +4 | Active botnet C2 — strongest signal |
| **Tor exit nodes** | +3 | Deliberately anonymized source |
| **Sentinel TI** | — | Your own curated indicators |
| **Blocklist.de** | +2 | Known attacking IP; broad, so supporting evidence only |

`FeedMatches` shows which fired, so triage doesn't require re-checking each one.

---

## ⚖️ Additional scoring

- 🔥 **Heavy bombing** — more than 20 denials
- 🌍 **Multi-region** — prompts originating from more than one country

Output also carries the targeted apps, OS, browser, cities, and the exact authentication window, so you can tell a Teams-only spray from one hitting a VPN endpoint.

---

## 🔍  KQL

```
// ============================================================
// MFA FATIGUE / PUSH BOMBING - Multi-Feed Enriched
// ============================================================
// MITRE ATT&CK:
//   Tactic:    Credential Access, Initial Access
//   Technique: T1621 - Multi-Factor Authentication Request Generation
//              T1078 - Valid Accounts
//              T1090.003 - Proxy: Multi-hop Proxy (Tor)
// ============================================================
// Detects MFA push bombing (many denials in a short window), flags when
// the user CAVED (spam ended in success), and enriches the source IP
// against Feodo C2, Tor exit nodes, and Blocklist.de.
// ============================================================
let LookbackTime = 7d;
let SpamWindow = 10m;
let MinFailedAttempts = 5;
// === Feed 1: Feodo Tracker - Botnet C2 IPs ===
let Feodo_IPs = materialize(
    externaldata(Indicator:string)
    [@"https://feodotracker.abuse.ch/downloads/ipblocklist.txt"]
    with (format="txt")
    | where Indicator matches regex @"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    | distinct Indicator
);
// === Feed 2: Tor Exit Nodes ===
let Tor_IPs = materialize(
    externaldata(Indicator:string)
    [@"https://check.torproject.org/torbulkexitlist"]
    with (format="txt")
    | where Indicator matches regex @"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    | distinct Indicator
);
// === Feed 3: Blocklist.de - Attacking IPs ===
let Blocklist_IPs = materialize(
    externaldata(Indicator:string)
    [@"https://lists.blocklist.de/lists/all.txt"]
    with (format="txt")
    | where Indicator matches regex @"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    | distinct Indicator
);
// === Sentinel TI (kept from before) ===
let TI_IPs = ThreatIntelligenceIndicator
    | where TimeGenerated > ago(30d)
    | where Active == true and isnotempty(NetworkIP)
    | distinct NetworkIP;
SigninLogs
| where TimeGenerated > ago(LookbackTime)
| extend
    DeviceDetail    = todynamic(DeviceDetail),
    LocationDetails = todynamic(LocationDetails)
| extend
    OS      = tostring(DeviceDetail.operatingSystem),
    Browser = tostring(DeviceDetail.browser),
    City    = tostring(LocationDetails.city),
    Region  = tostring(LocationDetails.countryOrRegion)
| where AuthenticationRequirement == "multiFactorAuthentication"
| mv-expand todynamic(AuthenticationDetails)
| extend AuthResult = tostring(parse_json(AuthenticationDetails).authenticationStepResultDetail)
// --- Aggregate per user + IP ---
| summarize
    FailedAttempts = countif(AuthResult has_any (
        "MFA denied; user declined the authentication",
        "MFA denied; user did not respond to mobile app notification",
        "MFA denied; duplicate authentication attempt",
        "user declined"
    )),
    SuccessfulAttempts = countif(AuthResult == "MFA successfully completed"),
    TotalPrompts   = count(),
    InvolvedOS     = make_set(OS, 5),
    InvolvedBrowser = make_set(Browser, 5),
    Cities         = make_set(City, 5),
    Regions        = make_set(Region, 5),
    Apps           = make_set(AppDisplayName, 10),
    StartTime      = min(TimeGenerated),
    EndTime        = max(TimeGenerated)
    by UserPrincipalName, IPAddress
| extend AuthenticationWindow = (EndTime - StartTime)
// --- Flag bombing ---
| where FailedAttempts >= MinFailedAttempts
    and AuthenticationWindow <= SpamWindow
// --- CRITICAL: did the user cave? ---
| extend UserCaved = SuccessfulAttempts > 0
// --- Enrich source IP against all feeds ---
| extend
    IsFeodoC2   = IPAddress in (Feodo_IPs),
    IsTorExit   = IPAddress in (Tor_IPs),
    IsBlocklist = IPAddress in (Blocklist_IPs),
    IsSentinelTI = IPAddress in (TI_IPs)
| extend IsMaliciousIP = IsFeodoC2 or IsTorExit or IsBlocklist or IsSentinelTI
| extend FeedMatches = strcat(
    iff(IsFeodoC2, "Feodo-C2 ", ""),
    iff(IsTorExit, "Tor-Exit ", ""),
    iff(IsBlocklist, "Blocklist.de ", ""),
    iff(IsSentinelTI, "Sentinel-TI ", "")
)
// --- Risk Score ---
| extend RiskScore = 5
                   + iff(UserCaved, 4, 0)
                   + iff(IsFeodoC2, 4, 0)          // C2 infra = strongest
                   + iff(IsTorExit, 3, 0)          // anonymized = very suspicious
                   + iff(IsBlocklist, 2, 0)        // attacking IP = supporting
                   + iff(FailedAttempts > 20, 2, 0)
                   + iff(array_length(Regions) > 1, 1, 0)
| extend Severity = case(
    UserCaved and IsMaliciousIP, "🔴 Critical - Likely Compromised",
    UserCaved,                    "🔴 Critical - User Approved",
    IsFeodoC2 or IsTorExit,       "🔴 Critical - Malicious Source",
    FailedAttempts > 20,          "🟠 High - Heavy Bombing",
    "🟡 Medium - MFA Spam"
)
| extend Name = tostring(split(UserPrincipalName, '@')[0]),
         UPNSuffix = tostring(split(UserPrincipalName, '@')[1])
| project
    StartTime,
    EndTime,
    Severity,
    RiskScore,
    UserPrincipalName,
    UserCaved,
    IsMaliciousIP,
    FeedMatches,
    FailedAttempts,
    SuccessfulAttempts,
    TotalPrompts,
    AuthenticationWindow,
    IPAddress,
    Regions,
    Cities,
    Apps,
    InvolvedOS,
    InvolvedBrowser
| extend timestamp = EndTime,
         AccountCustomEntity = UserPrincipalName,
         IPCustomEntity = IPAddress
| sort by RiskScore desc, UserCaved desc, FailedAttempts desc
```

---

## 📚 Reference

MITRE ATT&CK: T1621 (MFA Request Generation), T1078 (Valid Accounts), T1090.003 (Multi-hop Proxy / Tor).
