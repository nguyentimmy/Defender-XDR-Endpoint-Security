# Data Exfil

**Multi-vector exfiltration detection across endpoint, cloud, and mailbox telemetry.**

Runs fleet-wide by default, or scopes to a single device or user for investigation.

---

## Why this exists

Exfiltration rarely shows up as one obvious event. It's a sequence — collect, stage, compress, then move — and the move often uses a different channel than the one being monitored. An attacker who can't reach a file-sharing site will use email; a user walking out with data will use a USB drive.

This covers eight channels in a single view so the pattern is visible rather than scattered across separate queries. It's equally applicable to external intrusion and insider risk.

---

## What it searches for

| Section | Catches |
| --- | --- |
| **File-Sharing / Paste Uploads** | WeTransfer, MEGA, anonymous file hosts, paste sites, personal cloud storage |
| **Exfil Tooling** | `rclone`, `megacmd`, `azcopy`, WinSCP, FTP clients, cloud CLIs — with an upload verb |
| **Mass Archiving** | Bulk compression, weighted heavily when password-protected or targeting sensitive paths |
| **Removable Media** | USB mount events and bulk writes to non-system drives |
| **Bulk Cloud Download** | High-volume SharePoint / OneDrive file downloads |
| **Outbound Attachments** | External attachment volume, weighted higher for personal webmail recipients |
| **Mail Forwarding Rules** | Inbox and transport rules forwarding externally — the classic BEC method |
| **Connection Fan-Out** | High connection counts from non-browser processes, as a volume proxy |

---
## KQL
```
// ============================================================
// DATA EXFILTRATION HUNT - Workbook (Parameterized)
// ============================================================
// MITRE ATT&CK:
//   Tactic:    Collection, Exfiltration
//   Technique: T1567.002 - Exfiltration to Cloud Storage
//              T1567.003 - Exfiltration to Text Storage Sites
//              T1048     - Exfiltration Over Alternative Protocol
//              T1052.001 - Exfiltration over USB
//              T1560.001 - Archive Collected Data via Utility
//              T1114.003 - Email Collection: Forwarding Rule
//              T1074.001 - Local Data Staging
// ============================================================
// Multi-vector exfil hunt: uploads to file-sharing and paste sites, exfil
// tooling, mass archiving, removable media, bulk cloud download, outbound
// attachments, and forwarding rules.
// PARAMETERS: {TimeRange} (required), {DeviceName} and {UserPrincipalName}
// are OPTIONAL scoping filters - leave both empty for a fleet-wide sweep.
// ============================================================
let TargetDevice = "{DeviceName}";
let TargetUser = "{UserPrincipalName}";
// --- Tunable thresholds ---
let ArchiveThreshold = 5;
let AttachThreshold = 10;
let DownloadThreshold = 50;
let ConnFanoutThreshold = 1000;
let UsbWriteThreshold = 20;
// --- Sanctioned corporate cloud storage ---
let SanctionedCloud = dynamic([
    "sharepoint.com", "onedrive.com", "office.com",
    "microsoft.com", "windows.net"
]);
// --- Internal mail domains ---
let InternalDomains = dynamic([
    "yourdomain1.com", "yourdomain2.com"
]);
union isfuzzy=true
// ============================================================
// 1. UPLOADS TO FILE-SHARING / PASTE / PERSONAL CLOUD
// ============================================================
(
    DeviceNetworkEvents
    | where TimeGenerated {TimeRange}
    | where ActionType == "ConnectionSuccess"
    | where isnotempty(RemoteUrl)
    | where RemoteUrl has_any (
        "wetransfer.com", "mega.nz", "mega.io", "megaupload",
        "anonfiles.com", "transfer.sh", "filebin.net", "file.io",
        "ufile.io", "gofile.io", "pixeldrain.com", "bayfiles.com",
        "sendspace.com", "mediafire.com", "zippyshare.com",
        "catbox.moe", "temp.sh", "0x0.st", "uguu.se",
        "pastebin.com", "paste.ee", "ghostbin.com", "rentry.co",
        "controlc.com", "dpaste.com", "hastebin.com", "privatebin",
        "gist.github.com", "termbin.com",
        "dropbox.com", "box.com", "drive.google.com", "icloud.com",
        "pcloud.com", "sync.com", "tresorit.com", "degoo.com"
    )
    | where not(RemoteUrl has_any (SanctionedCloud))
    | extend IsPasteSite = RemoteUrl has_any ("pastebin", "paste.ee", "ghostbin", "rentry", "controlc", "dpaste", "hastebin", "privatebin", "gist.github", "termbin")
    | extend IsAnonHost = RemoteUrl has_any ("anonfiles", "transfer.sh", "filebin", "file.io", "ufile", "gofile", "catbox", "temp.sh", "0x0.st", "uguu", "bayfiles")
    | summarize
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated),
        EventCount = count(),
        Destinations = make_set(RemoteUrl, 10),
        AnyPaste = max(IsPasteSite),
        AnyAnon = max(IsAnonHost)
        by DeviceName, Account = InitiatingProcessAccountName, Process = InitiatingProcessFileName
    | extend Signal = "☁️ Upload to File-Sharing / Paste Site",
             RiskScore = 5 + (toint(AnyAnon) * 3) + (toint(AnyPaste) * 2),
             Detail = substring(strcat("Destinations: ", tostring(Destinations)), 0, 300)
    | project FirstSeen, LastSeen, Signal, RiskScore, DeviceName, Account, Process, EventCount, Detail
),
// ============================================================
// 2. EXFIL TOOLING - rclone, megacmd, WinSCP, azcopy, FTP
// ============================================================
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | extend CmdArgs = replace_regex(ProcessCommandLine, @'(?i)^\s*"?[^"]*?\.exe"?', "")
    | where FileName in~ (
        "rclone.exe", "megacmd.exe", "megaclient.exe", "mega.exe",
        "winscp.exe", "winscp.com", "psftp.exe", "pscp.exe",
        "filezilla.exe", "ftp.exe", "tftp.exe",
        "aws.exe", "azcopy.exe", "gsutil.exe", "s3cmd.exe",
        "curl.exe", "wget.exe"
    )
    | where CmdArgs has_any ("copy", "sync", "move", "upload", "put",
        "--transfers", "-T ", "cp ", "mput", "s3://", "b2:", "remote:")
        or CmdArgs contains "-F "
        or CmdArgs contains "--upload-file"
    | extend IsHighRiskTool = FileName in~ ("rclone.exe", "megacmd.exe", "megaclient.exe", "mega.exe", "azcopy.exe")
    | summarize
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated),
        EventCount = count(),
        Commands = make_set(substring(CmdArgs, 0, 200), 3),
        AnyHighRisk = max(IsHighRiskTool)
        by DeviceName, Account = AccountName, Process = FileName
    | extend Signal = "🚚 Exfiltration Tooling",
             RiskScore = 6 + (toint(AnyHighRisk) * 3),
             Detail = substring(strcat("Cmds: ", tostring(Commands)), 0, 300)
    | project FirstSeen, LastSeen, Signal, RiskScore, DeviceName, Account, Process, EventCount, Detail
),
// ============================================================
// 3. MASS ARCHIVING / STAGING (password-protected = stronger)
// ============================================================
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where FileName in~ (
        "7z.exe", "7za.exe", "7zG.exe", "winrar.exe", "rar.exe",
        "zip.exe", "tar.exe", "WinZip.exe", "wzzip.exe", "PeaZip.exe",
        "makecab.exe", "compact.exe"
    )
    | extend CmdArgs = replace_regex(ProcessCommandLine, @'(?i)^\s*"?[^"]*?\.exe"?', "")
    // " a " is a single term to has_any - must use contains
    | where CmdArgs contains " a "
        or CmdArgs contains "-mx"
        or CmdArgs contains "-r "
        or CmdArgs has_any ("compress", "archive", "-tzip", "-t7z", "cvf", "czf")
    | extend IsPasswordProtected = CmdArgs matches regex @"(?i)\s-(?:hp|p)[^\s]"
    | extend IsSensitiveTarget = CmdArgs has_any (
        "\\Documents", "\\Desktop", "\\Downloads", "\\Users\\",
        ".pst", ".ost", ".kdbx", ".pem", ".key", "\\Finance", "\\HR"
    )
    | summarize
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated),
        EventCount = count(),
        Commands = make_set(substring(CmdArgs, 0, 200), 3),
        AnyPassword = max(IsPasswordProtected),
        AnySensitive = max(IsSensitiveTarget)
        by DeviceName, Account = AccountName, Process = FileName
    | where EventCount > ArchiveThreshold or AnyPassword == true
    | extend Signal = "📦 Mass Archiving / Staging",
             RiskScore = 4 + (toint(AnyPassword) * 4) + (toint(AnySensitive) * 2),
             Detail = substring(strcat(iff(AnyPassword, "PASSWORD-PROTECTED | ", ""), "Cmds: ", tostring(Commands)), 0, 300)
    | project FirstSeen, LastSeen, Signal, RiskScore, DeviceName, Account, Process, EventCount, Detail
),
// ============================================================
// 4a. REMOVABLE MEDIA MOUNTED
// ============================================================
(
    DeviceEvents
    | where TimeGenerated {TimeRange}
    | where ActionType in ("UsbDriveMounted", "UsbDriveMount", "PnpDeviceConnected")
    | where tostring(AdditionalFields) has_any ("USB", "Removable", "DriveLetter")
    | summarize
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated),
        EventCount = count(),
        Details = make_set(substring(tostring(AdditionalFields), 0, 150), 3)
        by DeviceName, Account = InitiatingProcessAccountName, Process = InitiatingProcessFileName
    | extend Signal = "🔌 Removable Media Mounted",
             RiskScore = 4,
             Detail = substring(strcat("Device: ", tostring(Details)), 0, 300)
    | project FirstSeen, LastSeen, Signal, RiskScore, DeviceName, Account, Process, EventCount, Detail
),
// ============================================================
// 4b. BULK WRITES TO EXTERNAL / NON-SYSTEM DRIVE
// ============================================================
(
    DeviceFileEvents
    | where TimeGenerated {TimeRange}
    | where ActionType in ("FileCreated", "FileModified")
    | where FolderPath matches regex @"^[D-Zd-z]:\\"
    | where not(FolderPath startswith "\\\\")
    | summarize
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated),
        EventCount = count(),
        Files = make_set(FileName, 5),
        Paths = make_set(substring(FolderPath, 0, 80), 3)
        by DeviceName, Account = InitiatingProcessAccountName, Process = InitiatingProcessFileName
    | where EventCount > UsbWriteThreshold
    | extend Signal = "🔌 Bulk Writes to External Drive",
             RiskScore = 6,
             Detail = substring(strcat("Paths: ", tostring(Paths), " | Files: ", tostring(Files)), 0, 300)
    | project FirstSeen, LastSeen, Signal, RiskScore, DeviceName, Account, Process, EventCount, Detail
),
// ============================================================
// 5. BULK SHAREPOINT / ONEDRIVE DOWNLOAD
// ============================================================
(
    OfficeActivity
    | where TimeGenerated {TimeRange}
    | where Operation in ("FileDownloaded", "FileSyncDownloadedFull", "FileSyncDownloadedPartial")
    | summarize
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated),
        EventCount = count(),
        UniqueFiles = dcount(OfficeObjectId),
        SourceIPs = make_set(ClientIP, 5)
        by Account = UserId, Process = tostring(UserAgent)
    | where EventCount > DownloadThreshold
    | extend Signal = "📥 Bulk Cloud File Download",
             RiskScore = 5,
             DeviceName = "",
             Detail = substring(strcat("Files: ", tostring(UniqueFiles), " | IPs: ", tostring(SourceIPs)), 0, 300)
    | project FirstSeen, LastSeen, Signal, RiskScore, DeviceName, Account, Process, EventCount, Detail
),
// ============================================================
// 6. OUTBOUND ATTACHMENTS TO EXTERNAL DOMAINS
// ============================================================
(
    EmailEvents
    | where TimeGenerated {TimeRange}
    | where EmailDirection == "Outbound"
    | where AttachmentCount > 0
    | extend RecipientDomain = tolower(tostring(split(RecipientEmailAddress, "@")[1]))
    | where isnotempty(RecipientDomain)
    | where not(RecipientDomain has_any (InternalDomains))
    | extend IsPersonalWebmail = RecipientDomain has_any (
        "gmail.com", "outlook.com", "hotmail.com", "yahoo.com",
        "aol.com", "proton.me", "protonmail.com", "gmx.com",
        "mail.ru", "yandex.com", "tutanota.com", "icloud.com"
    )
    | summarize
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated),
        EventCount = count(),
        TotalAttach = sum(AttachmentCount),
        UniqueRecipients = dcount(RecipientEmailAddress),
        RecipientDomains = make_set(RecipientDomain, 10),
        AnyPersonal = max(IsPersonalWebmail)
        by Account = SenderFromAddress
    | where TotalAttach > AttachThreshold
    | extend Signal = "📧 Outbound Attachments to External",
             RiskScore = 4 + (toint(AnyPersonal) * 3),
             DeviceName = "",
             Process = "",
             Detail = substring(strcat("Attachments: ", tostring(TotalAttach),
                      " | Recipients: ", tostring(UniqueRecipients),
                      " | Domains: ", tostring(RecipientDomains)), 0, 300)
    | project FirstSeen, LastSeen, Signal, RiskScore, DeviceName, Account, Process, EventCount, Detail
),
// ============================================================
// 7. MAIL FORWARDING RULES - classic BEC exfil
// ============================================================
(
    OfficeActivity
    | where TimeGenerated {TimeRange}
    | where Operation in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules",
        "Set-Mailbox", "Set-TransportRule", "New-TransportRule")
    | extend Params = tostring(Parameters)
    | where Params has_any ("ForwardTo", "ForwardAsAttachmentTo", "RedirectTo",
        "ForwardingSmtpAddress", "DeliverToMailboxAndForward", "BlindCopyTo")
    | extend ForwardsExternal = not(Params has_any (InternalDomains))
    | summarize
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated),
        EventCount = count(),
        Operations = make_set(Operation, 5),
        SourceIPs = make_set(ClientIP, 5),
        Samples = make_set(substring(Params, 0, 200), 2),
        AnyExternal = max(ForwardsExternal)
        by Account = UserId
    | extend Signal = "📬 Mail Forwarding Rule Created",
             RiskScore = 6 + (toint(AnyExternal) * 3),
             DeviceName = "",
             Process = "",
             Detail = substring(strcat(iff(AnyExternal, "EXTERNAL TARGET | ", ""),
                      tostring(Operations), " | IPs: ", tostring(SourceIPs),
                      " | ", tostring(Samples)), 0, 300)
    | project FirstSeen, LastSeen, Signal, RiskScore, DeviceName, Account, Process, EventCount, Detail
),
// ============================================================
// 8. CONNECTION FAN-OUT (volume proxy - Defender has no byte counts)
// ============================================================
(
    DeviceNetworkEvents
    | where TimeGenerated {TimeRange}
    | where ActionType == "ConnectionSuccess"
    | where RemoteIPType == "Public"
    | where not(InitiatingProcessFileName in~ (
        "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe",
        "msedgewebview2.exe", "teams.exe", "ms-teams.exe", "outlook.exe",
        "onedrive.exe", "svchost.exe", "backgroundtaskhost.exe",
        "searchapp.exe", "widgets.exe", "officeclicktorun.exe"
    ))
    | summarize
        EventCount = count(),
        UniqueRemoteIPs = dcount(RemoteIP),
        UniqueDomains = dcount(RemoteUrl),
        TopDestinations = make_set(RemoteIP, 5)
        by DeviceName, Account = InitiatingProcessAccountName,
           Process = InitiatingProcessFileName, HourBin = bin(TimeGenerated, 1h)
    | where EventCount > ConnFanoutThreshold
    | extend Signal = "📡 High Connection Fan-Out (volume proxy)",
             RiskScore = 4,
             FirstSeen = HourBin,
             LastSeen = HourBin + 1h,
             Detail = substring(strcat("Conns/hr: ", tostring(EventCount),
                      " | Unique IPs: ", tostring(UniqueRemoteIPs),
                      " | Domains: ", tostring(UniqueDomains)), 0, 300)
    | project FirstSeen, LastSeen, Signal, RiskScore, DeviceName, Account, Process, EventCount, Detail
),
// --- Schema pin so union stays stable when a section is empty ---
(
    datatable(FirstSeen:datetime, LastSeen:datetime, Signal:string, RiskScore:long,
              DeviceName:string, Account:string, Process:string,
              EventCount:long, Detail:string)[]
)
// ============================================================
// PARAMETER SCOPING (post-union)
// A device selection drops identity-only rows (blank DeviceName).
// A user selection matches on the local part so it works against both
// full UPNs (mailbox sections) and short usernames (endpoint sections).
// Both empty = fleet-wide sweep.
// ============================================================
| extend UserLocalPart = tostring(split(TargetUser, "@")[0])
| where isempty(TargetDevice) or DeviceName has TargetDevice
| where isempty(TargetUser) or Account has UserLocalPart
// ============================================================
// CONSOLIDATE & SCORE
// ============================================================
| extend Severity = case(
    RiskScore >= 9, "🔴 Critical",
    RiskScore >= 6, "🟠 High",
    RiskScore >= 4, "🟡 Medium",
    "🟢 Low"
)
| project
    FirstSeen,
    Severity,
    EventCount,
    Signal,
    DeviceName,
    Account,
    Process,
    Detail,
    RiskScore,
    LastSeen
| extend
    timestamp = FirstSeen,
    HostCustomEntity = DeviceName,
    AccountCustomEntity = Account
| sort by RiskScore desc, EventCount desc
```
