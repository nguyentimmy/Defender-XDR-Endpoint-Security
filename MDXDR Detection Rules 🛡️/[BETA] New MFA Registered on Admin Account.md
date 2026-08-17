# 🔐 New MFA Method Registered on Privileged Account

**Detection rule — fires when an authentication method is registered, changed, or deleted on an account holding a privileged directory role.**

---

## 🎯 Purpose

Detects registration, modification, or deletion of authentication methods on accounts holding privileged directory roles. Enriched with three context signals — registered by a different account, registered from a new IP, or registered shortly after a password reset — to separate routine enrollment from account takeover activity.

Intended for scheduled execution at 15-minute cadence. Multiple context signals stacking indicates a high-confidence takeover chain and warrants immediate response.

---

## 🔍 How it works

| Step | Logic |
| --- | --- |
| 1️⃣ | Build `PrivilegedAccounts` set from `IdentityInfo` (UEBA, filtered to accounts holding roles in the target list) unioned with the optional `PrivilegedAccounts` Watchlist |
| 2️⃣ | Materialize `KnownUserIPs` — successful sign-in IPs per privileged account over a 14-day baseline |
| 3️⃣ | Materialize `RecentPasswordResets` — successful password resets in the last 2 hours + rule window |
| 4️⃣ | Query `AuditLogs` for auth method registration, change, or deletion operations |
| 5️⃣ | Filter to operations targeting privileged accounts |
| 6️⃣ | Classify `MethodType` from `modifiedProperties` — Authenticator, Phone/SMS, FIDO2, Email, TAP, OATH |
| 7️⃣ | Tag three context signals: `RegisteredByOther`, `FromNewIP`, `AfterPasswordReset` |
| 8️⃣ | Score with weighted signals, label severity, and emit with entity mapping |

---

## ⚙️ Rule configuration

| Setting | Value |
| --- | --- |
| **Frequency** | 15 min |
| **Lookback** | 15 min |
| **Severity** | High (dynamic per score) |
| **Grouping** | Alert per event |
| **Ingestion delay buffer** | 10 min |
| **Baseline window** | 14 days |
| **Password reset correlation window** | 2 hours |
| **Entities** | Account, IP |

**Prerequisites (either or both):**

- **UEBA enabled** — the rule uses `IdentityInfo` to pull accounts with privileged roles assigned. Preferred source, keeps role assignments current.
- **`PrivilegedAccounts` Watchlist** — CSV-driven with a `UserPrincipalName` column. Backfills accounts UEBA may miss (guest admins, service accounts, delegated roles). If UEBA isn't available, comment out the UEBA source and rely on the Watchlist alone.

**Privileged roles tracked:** Global Administrator, Privileged Role Administrator, Privileged Authentication Administrator, Authentication Administrator, Security Administrator, Exchange/SharePoint/Teams Administrator, User Administrator, Application Administrator, Cloud Application Administrator, Conditional Access Administrator, Intune Administrator, Helpdesk Administrator, Password Administrator, Billing Administrator, Hybrid Identity Administrator, Domain Name Administrator, Partner Tier1/Tier2 Support.

---

## ⚖️ Scoring model

Base score of 5 for any auth method change on a privileged account, plus weighted context signals. `AfterPasswordReset` carries the most weight — it's the classic account-takeover sequence.

| Signal | Weight | Meaning |
| --- | --- | --- |
| **Base score** | 5 | Any auth method operation on a privileged account |
| **After password reset** | +4 | Method registered within 2 hours of a successful password reset — takeover chain |
| **Registered by other** | +3 | Actor ≠ target account (someone else made the change) |
| **From new IP** | +3 | Registration IP not in the target's 14-day sign-in baseline |
| **Temporary Access Pass** | +3 | TAP registration — can bypass MFA entirely, high-risk |
| **Method deleted** | +2 | Existing method removed — reducing legitimate access paths |

**Severity thresholds:**

| Score | Severity |
| --- | --- |
| 8+ | 🔴 High |
| < 8 | 🟡 Medium |

**Response guidance when fires:** verify against ticketing/change management. If the change wasn't scheduled or requested by the account owner, treat as suspected account compromise — revoke sessions, force password reset, review recent sign-ins for the target and actor, and check for any privileged operations performed in the intervening window.

---

## 🔍 KQL

```kql
// ============================================================
// [DETECTION RULE] New MFA Method Registered on Privileged Account
// ============================================================
// MITRE ATT&CK:
//   Tactic:    Persistence, Credential Access, Defense Evasion
//   Technique: T1556.006 - Modify Authentication Process: MFA
//              T1098.005 - Account Manipulation: Device Registration
//              T1078.004 - Valid Accounts: Cloud Accounts
// ============================================================
// RULE CONFIG: Frequency 15m | Lookup period 15m | Severity High
//              Event grouping: trigger an alert for each event
// ------------------------------------------------------------
// Fires when an authentication method is registered, changed, or deleted
// on an account holding a privileged directory role. Enriched with three
// context signals that separate routine enrollment from account takeover:
//   1. Registered by SOMEONE ELSE (admin-initiated)
//   2. Registered from an IP this user has NOT signed in from recently
//   3. Registered shortly AFTER a password reset (the takeover chain)
//
// ADMIN IDENTIFICATION: uses IdentityInfo (requires UEBA) unioned with an
// optional Watchlist. Defender cannot know which accounts you consider
// privileged - that mapping is the detection.
// ============================================================
let LookbackTime = 15m;
let IngestionDelay = 10m;
let BaselineWindow = 14d;
let ResetCorrelationWindow = 2h;
// --- Privileged roles that matter ---
let PrivilegedRoles = dynamic([
    "Global Administrator", "Privileged Role Administrator",
    "Privileged Authentication Administrator", "Authentication Administrator",
    "Security Administrator", "Exchange Administrator",
    "SharePoint Administrator", "Teams Administrator",
    "User Administrator", "Application Administrator",
    "Cloud Application Administrator", "Conditional Access Administrator",
    "Intune Administrator", "Helpdesk Administrator",
    "Password Administrator", "Billing Administrator",
    "Hybrid Identity Administrator", "Domain Name Administrator",
    "Partner Tier1 Support", "Partner Tier2 Support"
]);
// --- Source 1: IdentityInfo (UEBA). Comment out if UEBA is not enabled. ---
let AdminsFromUEBA = materialize(
    IdentityInfo
    | where TimeGenerated > ago(30d)
    | summarize arg_max(TimeGenerated, *) by AccountUPN
    | where isnotempty(AssignedRoles) and AssignedRoles != "[]"
    | mv-expand Role = todynamic(AssignedRoles) to typeof(string)
    | where Role in~ (PrivilegedRoles)
    | summarize Roles = make_set(Role, 10) by AdminUPN = tolower(AccountUPN)
);
// --- Source 2: optional Watchlist for accounts UEBA may miss ---
// Create a Watchlist 'PrivilegedAccounts' with a 'UserPrincipalName' column.
let AdminsFromWatchlist = materialize(
    _GetWatchlist('PrivilegedAccounts')
    | project AdminUPN = tolower(tostring(UserPrincipalName))
    | where isnotempty(AdminUPN)
    | extend Roles = dynamic(["(from Watchlist)"])
);
let PrivilegedAccounts = materialize(
    union isfuzzy=true (AdminsFromUEBA), (AdminsFromWatchlist)
    | summarize Roles = take_any(Roles) by AdminUPN
);
// --- Baseline: IPs this user has legitimately signed in from ---
let KnownUserIPs = materialize(
    SigninLogs
    | where TimeGenerated between (ago(BaselineWindow) .. ago(LookbackTime + IngestionDelay))
    | where ResultType == 0
    | where tolower(UserPrincipalName) in ((PrivilegedAccounts | project AdminUPN))
    | summarize KnownIPs = make_set(IPAddress, 200) by BaseUPN = tolower(UserPrincipalName)
);
// --- Recent password resets, for the takeover-chain correlation ---
let RecentPasswordResets = materialize(
    AuditLogs
    | where TimeGenerated > ago(LookbackTime + IngestionDelay + ResetCorrelationWindow)
    | where OperationName has_any (
        "Reset password", "Reset user password", "Change user password",
        "Change password (self-service)", "Reset password (by admin)",
        "Reset password (self-service)")
    | where Result =~ "success"
    | extend ResetTargetUPN = tolower(tostring(TargetResources[0].userPrincipalName))
    | where isnotempty(ResetTargetUPN)
    | project ResetTime = TimeGenerated, ResetTargetUPN,
              ResetBy = tostring(InitiatedBy.user.userPrincipalName)
);
// ============================================================
// CORE DETECTION - authentication method changes
// ============================================================
AuditLogs
| where TimeGenerated > ago(LookbackTime + IngestionDelay)
| where OperationName has_any (
    "User registered security info",
    "User changed default security info",
    "Admin registered security info",
    "Admin updated security info",
    "User deleted security info",
    "Admin deleted security info",
    "Add authentication method",
    "Update authentication method",
    "Delete authentication method",
    "Update StrongAuthentication",
    "User registered all required security info",
    "Register device"
)
| where Result =~ "success"
// --- Resolve the target account ---
| extend TargetUPN = tolower(coalesce(
    tostring(TargetResources[0].userPrincipalName),
    tostring(TargetResources[0].displayName),
    ""))
| where isnotempty(TargetUPN)
// --- Only privileged accounts ---
| join kind=inner (PrivilegedAccounts) on $left.TargetUPN == $right.AdminUPN
// --- Resolve the actor ---
| extend
    ActorUPN = tolower(coalesce(tostring(InitiatedBy.user.userPrincipalName), "")),
    ActorApp = tostring(InitiatedBy.app.displayName),
    ActorIP  = tostring(InitiatedBy.user.ipAddress)
| extend Actor = coalesce(iff(isnotempty(ActorUPN), ActorUPN, ""), ActorApp, "unknown")
// --- Extract the method type where the schema exposes it ---
| extend MethodDetail = tostring(TargetResources[0].modifiedProperties)
| extend MethodType = case(
    MethodDetail has_any ("MicrosoftAuthenticator", "PhoneAppNotification", "PhoneAppOTP"),
        "Authenticator App",
    MethodDetail has_any ("OneWaySMS", "PhoneNumber", "TwoWayVoiceMobile", "voice"),
        "Phone / SMS",
    MethodDetail has_any ("Fido2", "FIDO", "SecurityKey", "PasswordlessPhoneSignIn", "WindowsHelloForBusiness"),
        "FIDO2 / Passwordless",
    MethodDetail has_any ("Email", "AlternateEmail"),
        "Email",
    MethodDetail has_any ("TemporaryAccessPass", "TAP"),
        "⚠️ Temporary Access Pass",
    MethodDetail has "OathTokenMetadata",
        "OATH Token",
    "Unspecified"
)
// ============================================================
// CONTEXT SIGNAL 1 - registered by someone other than the account owner
// ============================================================
| extend RegisteredByOther = isnotempty(ActorUPN) and ActorUPN != TargetUPN
// ============================================================
// CONTEXT SIGNAL 2 - registration IP not in this user's baseline
// ============================================================
| join kind=leftouter (KnownUserIPs) on $left.TargetUPN == $right.BaseUPN
| extend FromNewIP = isnotempty(ActorIP)
    and array_length(KnownIPs) > 0
    and not(KnownIPs has_any (ActorIP))
// ============================================================
// CONTEXT SIGNAL 3 - password reset shortly before (takeover chain)
// ============================================================
| join kind=leftouter (RecentPasswordResets) on $left.TargetUPN == $right.ResetTargetUPN
| extend AfterPasswordReset = isnotempty(ResetTime)
    and ResetTime < TimeGenerated
    and datetime_diff('minute', TimeGenerated, ResetTime) <= (ResetCorrelationWindow / 1m)
// --- Deletion of an existing method is its own concern ---
| extend IsDeletion = OperationName has_any ("deleted security info", "Delete authentication method")
| extend IsTAP = MethodType has "Temporary Access Pass"
// ============================================================
// SCORING
// ============================================================
| extend RiskScore = 5
                   + (toint(AfterPasswordReset) * 4)
                   + (toint(RegisteredByOther)  * 3)
                   + (toint(FromNewIP)          * 3)
                   + (toint(IsTAP)              * 3)
                   + (toint(IsDeletion)         * 2)
| extend Severity = case(
    RiskScore >= 11, "High",
    RiskScore >= 8,  "High",
    "Medium"
)
| extend TriggerContext = trim(" ", strcat(
    iff(AfterPasswordReset, "AfterPasswordReset ", ""),
    iff(RegisteredByOther,  "RegisteredByOther ", ""),
    iff(FromNewIP,          "NewSourceIP ", ""),
    iff(IsTAP,              "TemporaryAccessPass ", ""),
    iff(IsDeletion,         "MethodDeleted ", "")
))
| extend
    AlertName = strcat("MFA method change on privileged account: ", TargetUPN),
    AlertDescription = strcat(
        OperationName, " on privileged account '", TargetUPN,
        "' (roles: ", tostring(Roles), ") by '", Actor, "'",
        iff(isnotempty(ActorIP), strcat(" from ", ActorIP), ""),
        ". Method: ", MethodType, ".",
        iff(AfterPasswordReset, " ⚠️ Occurred within 2h of a password reset - classic account takeover sequence.", ""),
        iff(RegisteredByOther, " ⚠️ Registered by a different account than the owner.", ""),
        iff(FromNewIP, " ⚠️ Source IP not seen in this user's sign-ins over the baseline window.", ""))
| project
    TimeGenerated,
    Severity,
    RiskScore,
    TriggerContext,
    TargetAccount = TargetUPN,
    PrivilegedRoles = Roles,
    Operation = OperationName,
    MethodType,
    Actor,
    ActorIP,
    RegisteredByOther,
    FromNewIP,
    AfterPasswordReset,
    IsDeletion,
    AlertName,
    AlertDescription,
    CorrelationId
| extend
    timestamp             = TimeGenerated,
    AccountCustomEntity   = TargetAccount,
    IPCustomEntity        = ActorIP
| sort by RiskScore desc, TimeGenerated desc
```

---

## 📚 Reference

MITRE ATT&CK: T1556.006 (Modify Authentication Process: MFA), T1098.005 (Account Manipulation: Device Registration), T1078.004 (Valid Accounts: Cloud Accounts).