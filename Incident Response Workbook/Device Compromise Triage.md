
# Device Compromise Triage

**On-demand post-compromise investigation for a single endpoint.**

Parameterized Microsoft Sentinel / Defender XDR queries for post-compromise investigation.

Traditionally, working a suspect device or account means opening a dozen separate queries across process, registry, network, identity, and mailbox telemetry — then lining up timestamps by hand. During an active incident, that setup work is the bottleneck, not the analysis.

These consolidate it into a single parameterized view. Pick an entity, pick a time range, get a chronological timeline in seconds. No query editing, no copy-pasting between tabs, no reconstructing the sequence manually.

---

## Why this exists

Investigating a suspect endpoint normally means running a dozen separate hunts — process, registry, network, and file telemetry — then correlating the results by hand. During an active incident that setup work is the bottleneck, not the analysis. This collapses ten detection categories into one parameterized view.

Use it when a device surfaces in an alert, appears on the endpoint dashboard, or is named by a user under investigation.

---

## What it searches for

| Category | Signals |
| --- | --- |
| **Persistence** | Run keys, RunOnce, Winlogon Shell/Userinit, scheduled tasks, service creation |
| **Credential Access** | LSASS dumping, Mimikatz, procdump, comsvcs, nanodump, pypykatz |
| **Defense Evasion** | Defender tampering, event log clearing, auditpol, USN journal deletion, AMSI/ETW bypass |
| **Ransomware Prep** | Shadow copy deletion, `bcdedit` recovery sabotage, backup catalog destruction |
| **Discovery** | AD enumeration, BloodHound/SharpHound, Kerberos/SPN recon, cloud identity recon, share/session and host enumeration |
| **Lateral Movement** | PsExec, WMI remote execution, PowerShell remoting, admin share access |
| **Network Egress** | LOLBins (PowerShell, rundll32, mshta, certutil) reaching external infrastructure |
| **Backdoor Shells** | Netcat/socat reverse shells, PowerShell TCP one-liners, named-pipe shells, web shells |
| **Remote Access** | Unauthorized RATs and tunneling tools (ngrok, chisel, frp, cloudflared) |
| **Defender Detections** | Native AV, ASR, Exploit Guard, and SmartScreen hits on the host |

---
## KQL
```
// ============================================================
// DEVICE COMPROMISE TRIAGE - Workbook (Parameterized)
// ============================================================
// MITRE ATT&CK:
//   T1547 / T1543 - Persistence: autostart, scheduled tasks, services
//   T1003.001     - Credential Access: LSASS memory
//   T1562 / T1070 - Defense Evasion: impair defenses, indicator removal
//   T1490         - Impact: inhibit system recovery
//   T1087 / T1069 / T1482 / T1558 - Discovery and Kerberos recon
//   T1021         - Lateral Movement: remote services
//   T1071 / T1572 - Command and Control: web protocols, tunneling
//   T1219         - Remote Access Software
// ============================================================
// PARAMETERS: {DeviceName}, {TimeRange}
// ============================================================
let TargetDevice = "{DeviceName}";
let BenignParents = dynamic([
    "qualysagent.exe", "msedge.exe", "msedgewebview2.exe",
    "MicrosoftEdgeUpdate.exe", "IntuneManagementExtension.exe",
    "backgroundTaskHost.exe"
]);
let HardSignalKeywords = dynamic([
    "Credential Access", "Ransomware Prep", "Backdoor", "Defense Evasion"
]);
union isfuzzy=true
// ============================================================
// 1. PERSISTENCE - autostart keys, scheduled tasks, services
// ============================================================
(
    DeviceRegistryEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
    | where RegistryKey has_any ("CurrentVersion\\Run", "CurrentVersion\\RunOnce",
        "Winlogon\\Shell", "Winlogon\\Userinit", "Policies\\Explorer\\Run")
    | project TimeGenerated, Signal = "🔧 Registry Persistence", DeviceName,
              Account = InitiatingProcessAccountName,
              InitiatingProcess = InitiatingProcessFileName,
              InitiatingProcessCmd = InitiatingProcessCommandLine,
              ChildProcess = "",
              SHA256 = InitiatingProcessSHA256,
              Detail = strcat("Reg: ", RegistryValueName, " = ", substring(RegistryValueData, 0, 200))
),
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | extend CmdArgs = replace_regex(ProcessCommandLine, @'(?i)^\s*"?[^"]*?\.exe"?', "")
    | where CmdArgs has_any ("schtasks /create", "New-ScheduledTask", "Register-ScheduledTask",
        "sc create", "New-Service", "sc.exe create")
    | project TimeGenerated, Signal = "🔧 Task/Service Persistence", DeviceName,
              Account = AccountName,
              InitiatingProcess = InitiatingProcessFileName,
              InitiatingProcessCmd = InitiatingProcessCommandLine,
              ChildProcess = FileName,
              SHA256,
              Detail = strcat("Task/Service: ", substring(CmdArgs, 0, 250))
),
// ============================================================
// 2. CREDENTIAL ACCESS - LSASS dumping, credential tooling
// ============================================================
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | extend CmdArgs = replace_regex(ProcessCommandLine, @'(?i)^\s*"?[^"]*?\.exe"?', "")
    | where CmdArgs has_any ("Mimikatz", "sekurlsa", "logonpasswords", "lsadump",
        "procdump", "comsvcs.dll", "MiniDumpWriteDump", "nanodump",
        "\\lsass", "lsass.dmp", "Out-Minidump", "pypykatz")
        or (CmdArgs has "comsvcs" and CmdArgs has "lsass")
    | project TimeGenerated, Signal = "🔑 Credential Access", DeviceName,
              Account = AccountName,
              InitiatingProcess = InitiatingProcessFileName,
              InitiatingProcessCmd = InitiatingProcessCommandLine,
              ChildProcess = FileName,
              SHA256,
              Detail = strcat("Cred access: ", substring(CmdArgs, 0, 250))
),
// ============================================================
// 3. DEFENSE EVASION - Defender tamper, log clearing, AMSI bypass
// ============================================================
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | extend CmdArgs = replace_regex(ProcessCommandLine, @'(?i)^\s*"?[^"]*?\.exe"?', "")
    | where CmdArgs has_any (
        "DisableRealtimeMonitoring", "DisableBehaviorMonitoring", "Add-MpPreference -ExclusionPath",
        "wevtutil cl", "Clear-EventLog", "auditpol /clear", "fsutil usn deletejournal",
        "TamperProtection", "AmsiScanBuffer", "amsiInitFailed")
    | project TimeGenerated, Signal = "🥷 Defense Evasion", DeviceName,
              Account = AccountName,
              InitiatingProcess = InitiatingProcessFileName,
              InitiatingProcessCmd = InitiatingProcessCommandLine,
              ChildProcess = FileName,
              SHA256,
              Detail = strcat("Evasion: ", substring(CmdArgs, 0, 250))
),
// ============================================================
// 4. RANSOMWARE PREP - shadow copy / backup destruction
// ============================================================
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | extend CmdArgs = replace_regex(ProcessCommandLine, @'(?i)^\s*"?[^"]*?\.exe"?', "")
    | where CmdArgs has_any ("vssadmin delete shadows", "wmic shadowcopy delete",
        "Win32_ShadowCopy", "bcdedit /set recoveryenabled no", "wbadmin delete catalog",
        "vssadmin resize shadowstorage")
    | project TimeGenerated, Signal = "💥 Ransomware Prep", DeviceName,
              Account = AccountName,
              InitiatingProcess = InitiatingProcessFileName,
              InitiatingProcessCmd = InitiatingProcessCommandLine,
              ChildProcess = FileName,
              SHA256,
              Detail = strcat("Recovery sabotage: ", substring(CmdArgs, 0, 250))
),
// ============================================================
// 5. DISCOVERY - recon, categorized by target
// ============================================================
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | extend CmdArgs = replace_regex(ProcessCommandLine, @'(?i)^\s*"?[^"]*?\.exe"?', "")
    | extend ReconCategory = case(
        CmdArgs has_any ("net group \"domain admins\"", "net group \"enterprise admins\"",
            "net group \"domain controllers\"", "net localgroup administrators",
            "net accounts /domain", "dsquery", "dsget", "adfind",
            "Get-ADUser", "Get-ADGroup", "Get-ADComputer", "Get-ADDomain",
            "Get-DomainUser", "Get-NetUser", "Get-NetGroup", "Get-NetComputer",
            "Get-DomainController", "Get-NetDomainController"),
            "🔴 AD Enumeration",
        CmdArgs has_any ("SharpHound", "Invoke-BloodHound", "-CollectionMethod",
            "bloodhound", "azurehound", "Get-DomainTrust", "Get-ForestTrust"),
            "🔴 BloodHound/AD Mapping",
        CmdArgs has_any ("setspn -q", "setspn -l", "Get-DomainSPNTicket",
            "Invoke-Kerberoast", "GetUserSPNs", "Rubeus kerberoast", "kerberoast"),
            "🔴 Kerberos/SPN Recon",
        CmdArgs has_any ("az account", "az ad", "aws sts get-caller-identity",
            "aws iam", "gcloud auth", "Get-AzureADUser", "Get-MgUser",
            "Connect-AzAccount", "Get-AzRoleAssignment", "kubectl get secrets"),
            "🔴 Cloud/Identity Recon",
        CmdArgs has_any ("net view", "net share", "net session", "net use",
            "Get-NetShare", "Get-NetSession", "Find-DomainShare", "Invoke-ShareFinder",
            "PsLoggedon", "quser", "qwinsta", "query session", "query user"),
            "🟠 Share/Session Discovery",
        CmdArgs has_any ("net user", "net localgroup", "whoami /priv", "whoami /groups",
            "whoami /all", "Get-LocalUser", "Get-LocalGroupMember", "cmdkey /list",
            "wmic useraccount", "wmic group"),
            "🟠 Local Account/Priv Enum",
        (CmdArgs has_any ("Get-MpComputerStatus", "Get-MpPreference", "sc query windefend",
            "sc queryex", "tasklist /svc", "fltmc", "driverquery", "Get-Service")
            and CmdArgs has_any ("defender", "crowdstrike", "sentinel", "carbonblack",
                "cylance", "sophos", "mcafee", "symantec", "falcon")),
            "🟠 Security Product Discovery",
        CmdArgs has_any ("ipconfig", "arp -a", "route print", "netstat",
            "nltest /dclist", "nltest /domain_trusts", "nbtstat",
            "Get-NetNeighbor", "Resolve-DnsName", "ping -n", "for /l"),
            "🟡 Network Discovery",
        CmdArgs has_any ("systeminfo", "hostname", "wmic os", "wmic computersystem",
            "Get-ComputerInfo", "Get-WmiObject Win32_", "Get-CimInstance",
            "reg query", "wmic qfe", "wmic product"),
            "🟡 Host/System Enum",
        "🟡 Other Recon"
    )
    | where ReconCategory != "🟡 Other Recon"
        or FileName in~ ("whoami.exe", "net.exe", "net1.exe", "nltest.exe",
            "systeminfo.exe", "ipconfig.exe", "arp.exe", "route.exe",
            "quser.exe", "tasklist.exe", "netstat.exe", "wmic.exe", "dsquery.exe")
    | project TimeGenerated, Signal = "🔍 Discovery/Recon", DeviceName,
              Account = AccountName,
              InitiatingProcess = InitiatingProcessFileName,
              InitiatingProcessCmd = InitiatingProcessCommandLine,
              ChildProcess = FileName,
              SHA256,
              Detail = strcat(ReconCategory, ": ", FileName, " ", substring(ProcessCommandLine, 0, 200))
),
// ============================================================
// 6. LATERAL MOVEMENT - remote exec, PsExec, WMI, admin shares
// ============================================================
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | extend CmdArgs = replace_regex(ProcessCommandLine, @'(?i)^\s*"?[^"]*?\.exe"?', "")
    | where FileName in~ ("psexec.exe", "psexesvc.exe", "paexec.exe", "wmic.exe")
        or CmdArgs has_any ("Invoke-Command", "Enter-PSSession", "New-PSSession",
            "wmic /node", "\\admin$", "\\c$", "Invoke-WMIMethod", "Invoke-SMBExec")
    | project TimeGenerated, Signal = "↔️ Lateral Movement", DeviceName,
              Account = AccountName,
              InitiatingProcess = InitiatingProcessFileName,
              InitiatingProcessCmd = InitiatingProcessCommandLine,
              ChildProcess = FileName,
              SHA256,
              Detail = strcat("Lateral: ", FileName, " ", substring(CmdArgs, 0, 200))
),
// ============================================================
// 7. NETWORK EGRESS - LOLBins reaching public infrastructure
// ============================================================
(
    DeviceNetworkEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where InitiatingProcessFileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe",
        "rundll32.exe", "regsvr32.exe", "mshta.exe", "wscript.exe", "cscript.exe", "certutil.exe")
    | where RemoteIPType == "Public"
    | where not(tolower(RemoteUrl) matches regex
        @"^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|169\.254\.|localhost)")
    // Connectivity probes are not egress
    | where not(InitiatingProcessCommandLine contains "OpenRead"
        and InitiatingProcessCommandLine contains "CanRead")
    | where not(tolower(RemoteUrl) has_any ("google.com", "gstatic.com",
        "msftconnecttest.com", "msftncsi.com"))
    | project TimeGenerated, Signal = "🌐 LOLBin Network Egress", DeviceName,
              Account = InitiatingProcessAccountName,
              InitiatingProcess = InitiatingProcessFileName,
              InitiatingProcessCmd = InitiatingProcessCommandLine,
              ChildProcess = "",
              SHA256 = InitiatingProcessSHA256,
              Detail = strcat("Egress: ", InitiatingProcessFileName, " -> ",
                             coalesce(RemoteUrl, RemoteIP), ":", RemotePort)
),
// ============================================================
// 8. NATIVE DEFENDER DETECTIONS on this host
// ============================================================
(
    DeviceEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where ActionType has_any ("AntivirusDetection", "AntivirusReport",
        "SecurityLogCleared", "AsrLsassCredentialTheftBlocked",
        "ExploitGuardNetworkProtectionBlocked", "SmartScreenUrlWarning")
    | project TimeGenerated, Signal = "🛡️ Defender Detection", DeviceName,
              Account = InitiatingProcessAccountName,
              InitiatingProcess = InitiatingProcessFileName,
              InitiatingProcessCmd = InitiatingProcessCommandLine,
              ChildProcess = FileName,
              SHA256,
              Detail = strcat(ActionType, " | ", substring(tostring(AdditionalFields), 0, 200))
),
// ============================================================
// 9. BACKDOOR / REVERSE SHELL - interactive C2 channels
// ============================================================
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | extend CmdArgs = replace_regex(ProcessCommandLine, @'(?i)^\s*"?[^"]*?\.exe"?', "")
    | where CmdArgs has_any ("nc.exe -e", "ncat", "-e cmd", "-e /bin/sh", "-e powershell",
            "socat", "/bin/bash -i", "bash -i", "sh -i")
        or (CmdArgs has "System.Net.Sockets.TCPClient" and CmdArgs has_any ("GetStream", "sendback", "iex"))
        or CmdArgs has_any ("Invoke-PowerShellTcp", "Nishang", "powercat",
            "Invoke-Shellcode", "Invoke-ReverseShell")
        or (CmdArgs has "\\\\.\\pipe\\" and CmdArgs has_any ("cmd", "powershell"))
        or (CmdArgs has_any ("python", "python3") and CmdArgs has_any ("socket.socket", "SOCK_STREAM", "pty.spawn"))
        or (InitiatingProcessFileName in~ ("w3wp.exe", "httpd.exe", "nginx.exe", "tomcat.exe", "php-cgi.exe")
            and FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe"))
    | project TimeGenerated, Signal = "🐚 Backdoor / Reverse Shell", DeviceName,
              Account = AccountName,
              InitiatingProcess = InitiatingProcessFileName,
              InitiatingProcessCmd = InitiatingProcessCommandLine,
              ChildProcess = FileName,
              SHA256,
              Detail = strcat("Shell: ", FileName, " ", substring(CmdArgs, 0, 250))
),
// ============================================================
// 10. UNAUTHORIZED REMOTE TOOLS / TUNNELS
// ============================================================
(
    DeviceProcessEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where FileName in~ (
        "AnyDesk.exe", "RustDesk.exe", "QuickAssist.exe", "AeroAdmin.exe",
        "Supremo.exe", "ammyy.exe", "aa_v3.exe", "GetScreen.exe",
        "ScreenConnect.Client.exe", "ConnectWiseControl.Client.exe",
        "SplashtopSOS.exe", "LogMeIn.exe", "GoToAssist.exe",
        "ZohoAssist.exe", "RemotePC.exe", "meshagent.exe", "dwagent.exe",
        "RemoteUtilities.exe", "rutserv.exe", "Radmin.exe",
        "winvnc.exe", "tvnserver.exe", "uvnc_service.exe", "vncviewer.exe",
        "ngrok.exe", "frpc.exe", "chisel.exe", "cloudflared.exe", "plink.exe")
    | where FileName !in~ ("TeamViewer.exe", "TeamViewer_Service.exe", "tv_w32.exe",
        "tv_x64.exe", "BeyondTrust.exe", "bomgar-scc.exe", "raserver.exe")
    | extend IsTunneler = FileName in~ ("ngrok.exe", "frpc.exe", "chisel.exe", "cloudflared.exe", "plink.exe")
    | project TimeGenerated, Signal = iff(IsTunneler, "🕳️ Tunneling Tool", "🖥️ Unauthorized Remote Tool"),
              DeviceName, Account = AccountName,
              InitiatingProcess = InitiatingProcessFileName,
              InitiatingProcessCmd = InitiatingProcessCommandLine,
              ChildProcess = FileName,
              SHA256,
              Detail = strcat(iff(IsTunneler, "Tunnel: ", "RAT: "), FileName, " ", substring(ProcessCommandLine, 0, 200))
),
// --- Schema pin keeps union column order and types stable ---
(
    datatable(TimeGenerated:datetime, Signal:string, DeviceName:string, Account:string,
              InitiatingProcess:string, InitiatingProcessCmd:string, ChildProcess:string,
              SHA256:string, Detail:string)[]
)
// ============================================================
// NOISE SUPPRESSION - hard signals bypass this entirely
// ============================================================
| extend IsHardSignal = Signal has_any (HardSignalKeywords)
| extend IsBenignParent =
    InitiatingProcess in~ (BenignParents)
    or InitiatingProcessCmd contains "\\Microsoft Intune Management Extension\\Content\\DetectionScripts\\"
    or (InitiatingProcessCmd contains "-ExecutionPolicy AllSigned"
        and InitiatingProcessCmd contains "SessionState.LanguageMode")
    or InitiatingProcessCmd contains "--msedgewebview"
    or (InitiatingProcess =~ "svchost.exe"
        and (InitiatingProcessCmd contains "-s DPS"
             or InitiatingProcessCmd contains "-s SysMain"
             or InitiatingProcessCmd contains "-s DiagTrack"))
| where IsHardSignal or not(IsBenignParent)
| extend InitiatingProcessCmd = substring(InitiatingProcessCmd, 0, 120)
| extend Detail = substring(Detail, 0, 150)
| project TimeGenerated, Signal, DeviceName, Account,
          InitiatingProcess, ChildProcess, InitiatingProcessCmd, SHA256, Detail
| sort by TimeGenerated desc
```
