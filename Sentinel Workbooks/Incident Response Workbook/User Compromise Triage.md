
# User Compromise Triage

**On-demand post-compromise investigation for a single account.**

Select a user and time range to get a chronological timeline of identity and mailbox activity following a suspected compromise. Built for speed during active BEC and impersonation investigations.

---

## Why this exists

Account compromise plays out across Entra ID sign-in logs, directory audit logs, and Exchange mailbox activity — three different tables with three different schemas. Reconstructing what an attacker did to an account means querying all of them and lining up timestamps manually.

This unifies them into one timeline. Use it when a user is named in a phishing report, appears in a risky sign-in alert, or is identified during device triage.

---

## What it searches for

| Category | Signals |
| --- | --- |
| **MFA Changes** | New authentication methods registered, device registration |
| **Account Takeover** | MFA methods deleted, password resets, device unregistration |
| **Mailbox Rules** | Inbox and transport rules with forwarding, redirect, or blind-copy targets |
| **Risky Sign-ins** | Entra ID risk detections, `atRisk` and `confirmedCompromised` states |
| **Rare Geography** | Sign-ins from countries unusual **for this specific user**, not globally |
| **Malicious IPs** | Logons correlated against threat-intel feeds (botnet C2, Tor exit nodes) |
| **OAuth Consent** | Application permission grants — persistent access that survives a password reset |
| **Mailbox Export** | eDiscovery, compliance search, and bulk mail export operations |

---

## KQL

```
// ============================================================
// USER COMPROMISE TRIAGE - Workbook (Parameterized)
// ============================================================
// MITRE ATT&CK:
//   T1098.005 - Account Manipulation: Device Registration
//   T1556.006 - Modify Authentication Process: MFA
//   T1114.003 - Email Collection: Email Forwarding Rule
//   T1078.004 - Valid Accounts: Cloud Accounts
//   T1550.001 - Application Access Token
//   T1114.002 - Remote Email Collection
// ============================================================
// PARAMETERS: {UserPrincipalName}, {TimeRange}
// ============================================================
let TargetUser = "{UserPrincipalName}";
let InternalDomains = dynamic([
    "craneww.com", "cranesolutionsllc.com",
    "cranefreight.com", "magnointl.com"
]);
let MaliciousIPs = materialize(
    union
    (externaldata(ip:string)[@"https://feodotracker.abuse.ch/downloads/ipblocklist.txt"] with (format="txt")
        | where ip matches regex @"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"),
    (externaldata(ip:string)[@"https://check.torproject.org/torbulkexitlist"] with (format="txt")
        | where ip matches regex @"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    | distinct ip
);
union isfuzzy=true
// ============================================================
// 1. NEW MFA / AUTH METHODS REGISTERED
// ============================================================
(
    AuditLogs
    | where TimeGenerated {TimeRange}
    | where OperationName has_any (
        "Register security info", "Add security info",
        "User registered security info", "Admin registered security info",
        "Add authentication method", "Register device", "Update StrongAuthentication")
    | where tostring(TargetResources) has TargetUser or tostring(InitiatedBy) has TargetUser
    | project TimeGenerated, Signal = "🔐 New MFA/Auth Method", User = TargetUser,
              IPAddress = tostring(InitiatedBy.user.ipAddress),
              RawOperation = OperationName,
              Detail = strcat(OperationName, " | ", tostring(ResultDescription))
),
// ============================================================
// 2. MFA REMOVED / PASSWORD RESET - takeover eviction moves
// ============================================================
(
    AuditLogs
    | where TimeGenerated {TimeRange}
    | where OperationName has_any (
        "Delete authentication method", "User deleted security info",
        "Admin deleted security info", "Reset password (self-service)",
        "Reset user password", "Change user password", "Unregister device")
    | where tostring(TargetResources) has TargetUser or tostring(InitiatedBy) has TargetUser
    | project TimeGenerated, Signal = "🔓 MFA Removed / Password Reset", User = TargetUser,
              IPAddress = tostring(InitiatedBy.user.ipAddress),
              RawOperation = OperationName,
              Detail = strcat(OperationName, " | ", tostring(ResultDescription))
),
// ============================================================
// 3. MAILBOX FORWARDING / INBOX RULES
// ============================================================
(
    OfficeActivity
    | where TimeGenerated {TimeRange}
    | where UserId =~ TargetUser
    | where Operation in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules",
        "Set-Mailbox", "Set-MailboxAutoReplyConfiguration")
    | extend Params = tostring(Parameters)
    | where Params has_any ("ForwardTo", "ForwardAsAttachmentTo", "RedirectTo",
        "ForwardingSmtpAddress", "DeliverToMailboxAndForward")
    | extend ForwardsExternal = not(Params has_any (InternalDomains))
    | project TimeGenerated, Signal = "📬 Forwarding/Inbox Rule", User = UserId,
              IPAddress = ClientIP, RawOperation = Operation,
              Detail = strcat(iff(ForwardsExternal, "EXTERNAL TARGET | ", ""),
                             Operation, " | ", substring(Params, 0, 250))
),
// ============================================================
// 4. RISKY / ANOMALOUS SIGN-INS
// ============================================================
(
    SigninLogs
    | where TimeGenerated {TimeRange}
    | where UserPrincipalName =~ TargetUser
    | where RiskLevelDuringSignIn in ("high", "medium")
        or RiskState in ("atRisk", "confirmedCompromised")
        or (ResultType == 0 and RiskLevelAggregated in ("high", "medium"))
    | project TimeGenerated, Signal = "⚠️ Risky Sign-in", User = UserPrincipalName,
              IPAddress, RawOperation = tostring(RiskLevelDuringSignIn),
              Detail = strcat("Risk: ", RiskLevelDuringSignIn, " | ", AppDisplayName,
                             " | ", tostring(LocationDetails.countryOrRegion))
),
// ============================================================
// 5. RARE-COUNTRY SIGN-INS (baseline is per-user, not global)
// ============================================================
(
    SigninLogs
    | where TimeGenerated {TimeRange}
    | where UserPrincipalName =~ TargetUser
    | where ResultType == 0
    | extend Country = tostring(LocationDetails.countryOrRegion)
    | where isnotempty(Country)
    | summarize CountryCount = count(), LastSeen = max(TimeGenerated),
                IPs = make_set(IPAddress, 5) by Country
    | where CountryCount < 5
    | project TimeGenerated = LastSeen, Signal = "🌍 Rare Country Sign-in", User = TargetUser,
              IPAddress = tostring(IPs[0]), RawOperation = Country,
              Detail = strcat("Rare sign-in country: ", Country, " (", CountryCount, " sign-ins)")
),
// ============================================================
// 6. SIGN-INS FROM KNOWN-MALICIOUS IPs
// ============================================================
(
    SigninLogs
    | where TimeGenerated {TimeRange}
    | where UserPrincipalName =~ TargetUser
    | where IPAddress in (MaliciousIPs)
    | project TimeGenerated, Signal = "🚨 Malicious-IP Sign-in", User = UserPrincipalName,
              IPAddress, RawOperation = tostring(ResultType),
              Detail = strcat("Sign-in from flagged IP | Result: ", ResultType, " | ",
                             AppDisplayName, " | ", tostring(LocationDetails.countryOrRegion))
),
// ============================================================
// 7. OAUTH APP CONSENT GRANTS
// ============================================================
(
    AuditLogs
    | where TimeGenerated {TimeRange}
    | where OperationName has_any ("Consent to application", "Add OAuth2PermissionGrant",
        "Add delegated permission grant")
    | where tostring(InitiatedBy) has TargetUser or tostring(TargetResources) has TargetUser
    | project TimeGenerated, Signal = "🔗 OAuth App Consent", User = TargetUser,
              IPAddress = tostring(InitiatedBy.user.ipAddress),
              RawOperation = OperationName,
              Detail = strcat("OAuth consent: ", OperationName)
),
// ============================================================
// 8. MAILBOX EXPORT / eDISCOVERY - bulk mail exfil
// ============================================================
(
    OfficeActivity
    | where TimeGenerated {TimeRange}
    | where UserId =~ TargetUser or tostring(Parameters) has TargetUser
    | where Operation has_any ("New-MailboxExportRequest", "New-ComplianceSearch",
        "New-ComplianceSearchAction", "Set-ComplianceSearch",
        "SearchExportDownloaded", "New-MailboxSearch")
    | project TimeGenerated, Signal = "📤 Mailbox Export / eDiscovery", User = UserId,
              IPAddress = ClientIP, RawOperation = Operation,
              Detail = strcat(Operation, " | ", substring(tostring(Parameters), 0, 250))
)
// ============================================================
// UNIFIED TIMELINE
// ============================================================
| project TimeGenerated, Signal, User, IPAddress, RawOperation, Detail
| sort by TimeGenerated desc
```
