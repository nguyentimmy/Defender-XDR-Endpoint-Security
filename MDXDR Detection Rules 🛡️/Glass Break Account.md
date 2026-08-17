# 🚨 Break-Glass / Emergency Access Account Usage

**Detection rule — fires on any activity involving emergency-access accounts.**

---

## 🎯 Purpose

Break-glass accounts should have zero activity outside declared emergencies or scheduled tests. Any auth (success or failure), token refresh, or directory change involving these accounts fires. The `BreakGlassAccounts` Watchlist IS the detection — Defender has no way to know which accounts are emergency access without it.

---

## 🔍 How it works

Union of four branches keyed off the `BreakGlassAccounts` Watchlist.

| Branch | Trigger |
| --- | --- |
| **Interactive sign-in** | Any sign-in — success or failure. Failures = reconnaissance |
| **Non-interactive sign-in** | Token refresh — active session exists |
| **Actions BY the account** | Directory operations performed by the account |
| **Actions ON the account** | Password / MFA / role changes — attacker prep, or removal of emergency access |

---

## ⚙️ Rule configuration

| Setting | Value |
| --- | --- |
| **Frequency** | 15 min |
| **Lookback** | 15 min |
| **Severity** | High |
| **Grouping** | Alert per event |
| **Suppression** | None |
| **Entities** | Account, IP |

**Watchlist prerequisite:** Sentinel Watchlist `BreakGlassAccounts` with a `UserPrincipalName` column. Use `.onmicrosoft.com` addresses so accounts survive a federation outage.

```csv
UserPrincipalName,Purpose,Owner
emergency-admin-01@yourtenant.onmicrosoft.com,Primary,Security
emergency-admin-02@yourtenant.onmicrosoft.com,Secondary,Security
```

To skip the Watchlist, replace the `_GetWatchlist` block with `let BreakGlassAccounts = dynamic([...]);`.

**Design notes:**

- **Branch 4 catches the inverse attack** — attacker disabling or modifying break-glass accounts to remove your emergency access. Easy to miss without this.
- **Failed sign-ins matter** — someone knows the account exists and is trying it. Reconnaissance against last-resort access.
- **Expected fires:** ~4/year from quarterly testing. `ConditionalAccessStatus = notApplied` is expected (accounts excluded from CA by design).
- **On fire:** verify against change management. If not a declared incident or scheduled test, treat as suspected tenant compromise.

---

## 🔍 KQL

```kql
// ============================================================
// [DETECTION RULE] Break-Glass / Emergency Access Account Usage
// ============================================================
// MITRE ATT&CK:
//   Tactic:    Initial Access, Persistence, Privilege Escalation, Defense Evasion
//   Technique: T1078.004 - Valid Accounts: Cloud Accounts
//              T1098     - Account Manipulation
//              T1556.006 - Modify Authentication Process: MFA
//              T1531     - Account Access Removal
// ============================================================
// RULE CONFIG: Frequency 15m | Lookup period 15m | Severity High
//              Event grouping: trigger an alert for each event
// ------------------------------------------------------------
// Break-glass accounts should have ZERO activity outside a declared
// emergency or a scheduled test. Any authentication - success OR failure -
// and any modification of the account fires this rule.
//
// PREREQUISITE: a Sentinel Watchlist named 'BreakGlassAccounts' with a
// column 'UserPrincipalName'. That Watchlist IS the detection - Defender
// has no way to know which accounts are emergency access.
// ============================================================
let LookbackTime = 15m;
let IngestionDelay = 10m;
// --- Break-glass account list (Watchlist-driven) ---
let BreakGlassAccounts = materialize(
    _GetWatchlist('BreakGlassAccounts')
    | project BGAccount = tolower(tostring(UserPrincipalName))
    | where isnotempty(BGAccount)
    | distinct BGAccount
);
union isfuzzy=true
// ============================================================
// 1. INTERACTIVE SIGN-IN (any result - failures matter too)
// ============================================================
(
    SigninLogs
    | where TimeGenerated > ago(LookbackTime + IngestionDelay)
    | where tolower(UserPrincipalName) in (BreakGlassAccounts)
    | extend
        Country = tostring(LocationDetails.countryOrRegion),
        City    = tostring(LocationDetails.city),
        DeviceOS = tostring(DeviceDetail.operatingSystem),
        DeviceDisplayName = tostring(DeviceDetail.displayName),
        Browser = tostring(DeviceDetail.browser)
    | extend EventType = iff(ResultType == 0,
        "🔴 BREAK-GLASS SIGN-IN SUCCEEDED",
        "🟠 Break-Glass Sign-In Attempt FAILED")
    | project
        TimeGenerated,
        EventType,
        Account = UserPrincipalName,
        IPAddress,
        Location = strcat(City, ", ", Country),
        Application = AppDisplayName,
        ClientApp = ClientAppUsed,
        Detail = strcat(
            "Result: ", tostring(ResultType), " (", ResultDescription, ")",
            " | CA: ", ConditionalAccessStatus,
            " | Risk: ", coalesce(RiskLevelDuringSignIn, "none"),
            " | Device: ", coalesce(DeviceDisplayName, "unregistered"),
            " | OS: ", coalesce(DeviceOS, "-"),
            " | Browser: ", coalesce(Browser, "-")),
        InitiatedBy = UserPrincipalName
),
// ============================================================
// 2. NON-INTERACTIVE SIGN-IN (token refresh = live session)
// ============================================================
(
    AADNonInteractiveUserSignInLogs
    | where TimeGenerated > ago(LookbackTime + IngestionDelay)
    | where tolower(UserPrincipalName) in (BreakGlassAccounts)
    | extend Country = tostring(LocationDetails.countryOrRegion)
    | project
        TimeGenerated,
        EventType = "🔴 BREAK-GLASS TOKEN REFRESH (active session)",
        Account = UserPrincipalName,
        IPAddress,
        Location = Country,
        Application = AppDisplayName,
        ClientApp = ClientAppUsed,
        Detail = strcat("Result: ", tostring(ResultType),
                 " | ResourceDisplayName: ", coalesce(ResourceDisplayName, "-")),
        InitiatedBy = UserPrincipalName
),
// ============================================================
// 3. ACTIONS PERFORMED *BY* THE BREAK-GLASS ACCOUNT
// ============================================================
(
    AuditLogs
    | where TimeGenerated > ago(LookbackTime + IngestionDelay)
    | extend Actor = tolower(tostring(InitiatedBy.user.userPrincipalName))
    | where Actor in (BreakGlassAccounts)
    | project
        TimeGenerated,
        EventType = "🔴 BREAK-GLASS ACCOUNT PERFORMED DIRECTORY ACTION",
        Account = tostring(InitiatedBy.user.userPrincipalName),
        IPAddress = tostring(InitiatedBy.user.ipAddress),
        Location = "",
        Application = coalesce(LoggedByService, ""),
        ClientApp = "",
        Detail = strcat("Operation: ", OperationName,
                 " | Result: ", tostring(Result),
                 " | Target: ", substring(tostring(TargetResources), 0, 200)),
        InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
),
// ============================================================
// 4. ACTIONS PERFORMED *ON* THE BREAK-GLASS ACCOUNT
//    Password reset, MFA change, role removal, disable, delete.
//    An attacker modifying these accounts is preparing to use them -
//    or removing your emergency access before an attack.
// ============================================================
(
    AuditLogs
    | where TimeGenerated > ago(LookbackTime + IngestionDelay)
    | extend TargetBlob = tolower(tostring(TargetResources))
    | where TargetBlob has_any (BreakGlassAccounts)
    | extend Actor = tostring(InitiatedBy.user.userPrincipalName)
    | extend IsHighImpact = OperationName has_any (
        "Reset password", "Change password", "Update user",
        "Delete user", "Disable account", "Disable Strong Authentication",
        "Add authentication method", "Delete authentication method",
        "User registered security info", "User deleted security info",
        "Remove member from role", "Add member to role",
        "Update StrongAuthentication", "Block user")
    | project
        TimeGenerated,
        EventType = iff(IsHighImpact,
            "🔴 BREAK-GLASS ACCOUNT MODIFIED (high impact)",
            "🟠 Break-Glass Account Referenced in Directory Change"),
        Account = tostring(TargetResources[0].userPrincipalName),
        IPAddress = tostring(InitiatedBy.user.ipAddress),
        Location = "",
        Application = coalesce(LoggedByService, ""),
        ClientApp = "",
        Detail = strcat("Operation: ", OperationName,
                 " | Result: ", tostring(Result),
                 " | By: ", coalesce(Actor, tostring(InitiatedBy.app.displayName), "unknown")),
        InitiatedBy = coalesce(Actor, tostring(InitiatedBy.app.displayName), "unknown")
),
// --- Schema pin keeps union column order and types stable ---
(
    datatable(TimeGenerated:datetime, EventType:string, Account:string,
              IPAddress:string, Location:string, Application:string,
              ClientApp:string, Detail:string, InitiatedBy:string)[]
)
// ============================================================
// OUTPUT
// ============================================================
| extend
    Severity = iff(EventType startswith "🔴", "High", "Medium"),
    AlertName = strcat("Break-glass account activity: ", Account),
    AlertDescription = strcat(
        EventType, " for emergency access account '", Account,
        "'. These accounts should have zero activity outside a declared ",
        "emergency or scheduled test. Verify against change management ",
        "before dismissing. ", Detail)
| project
    TimeGenerated,
    Severity,
    EventType,
    Account,
    InitiatedBy,
    IPAddress,
    Location,
    Application,
    ClientApp,
    Detail,
    AlertName,
    AlertDescription
| extend
    timestamp           = TimeGenerated,
    AccountCustomEntity = Account,
    IPCustomEntity      = IPAddress
| sort by TimeGenerated desc
```

---

## 📚 Reference

MITRE ATT&CK: T1078.004 (Valid Accounts: Cloud Accounts), T1098 (Account Manipulation), T1556.006 (MFA Modification), T1531 (Account Access Removal).