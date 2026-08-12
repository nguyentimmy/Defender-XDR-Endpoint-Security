## 🖥️ Unapproved Remote Tools

**Detects remote-access software that isn't sanctioned tooling.**

RMM agents, remote-support clients, and VNC variants executing on endpoints — the primary delivery mechanism for vishing and helpdesk-impersonation attacks, where a caller convinces a user to install a remote tool and hands over the session.

- Flags scam-favored tools separately from general RMM (`IsHighAbuseTool`)
- Weights execution from user-writable paths, since attackers run portable builds rather than installing
- `IsPortableExec` catches tools running outside `Program Files`
- Approved internal tooling is excluded, so only *unauthorized* use surfaces

**Severity:** high-abuse tool + suspicious path = Critical. Either signal alone = High.

```
// ============================================================
// Unauthorized / Unapproved Remote Access Tools - Dashboard
// ============================================================
// Remote-access tool execution that isn't sanctioned tooling. TeamViewer
// and BeyondTrust excluded as approved; raserver.exe excluded as common.
// ============================================================
let LookupTime = 30d;
let HighAbuseTools = dynamic([
    "anydesk.exe", "rustdesk.exe", "quickassist.exe", "msra.exe",
    "aeroadmin.exe", "supremo.exe", "ammyy.exe", "aa_v3.exe",
    "getscreen.exe", "distant-desktop.exe", "litemanager.exe",
    "rutserv.exe", "rfusclient.exe"
]);
DeviceProcessEvents
| where Timestamp > ago(LookupTime)
| where FileName in~ (
    "AnyDesk.exe", "AnyDeskMSI.exe", "RustDesk.exe",
    "QuickAssist.exe", "msra.exe", "AeroAdmin.exe",
    "Supremo.exe", "SupremoHelper.exe", "ammyy.exe", "aa_v3.exe",
    "GetScreen.exe", "distant-desktop.exe", "LiteManager.exe",
    "ROMServer.exe", "ROMFUSClient.exe",
    "ScreenConnect.Client.exe", "ScreenConnect.ClientService.exe",
    "ConnectWiseControl.Client.exe", "connectwisecontrol.exe", "connectwisechat.exe",
    "SplashtopSOS.exe", "Splashtop.exe", "SRServer.exe", "SRManager.exe", "strwinclt.exe",
    "LogMeIn.exe", "LMIGuardianSvc.exe", "ramaint.exe",
    "GoToResolve.exe", "GoToAssist.exe", "g2ax_comm.exe",
    "ZohoAssist.exe", "ZA_Connect.exe", "ZMAgent.exe",
    "RemotePC.exe", "RPCSuite.exe", "RemotePCService.exe",
    "AteraAgent.exe", "Syncro.exe", "SyncroLive.Agent.Runner.exe",
    "NinjaRMMAgent.exe", "ninjarmm.exe", "AEMAgent.exe",
    "meshagent.exe", "dwagent.exe", "dwagsvc.exe",
    "RemoteUtilities.exe", "rutserv.exe", "rfusclient.exe",
    "Radmin.exe", "RServer3.exe", "famitrfc.exe",
    "winvnc.exe", "vncserver.exe", "vncviewer.exe",
    "tvnserver.exe", "uvnc_service.exe", "winvnc4.exe", "repeater.exe"
)
| where InitiatingProcessFileName !in~ ("TeamViewer.exe", "TeamViewer_Service.exe", "tv_w32.exe", "tv_x64.exe")
| where FileName !in~ ("TeamViewer.exe", "TeamViewer_Service.exe", "tv_w32.exe", "tv_x64.exe", "BeyondTrust.exe", "bomgar-scc.exe", "pbps.exe", "raserver.exe")
| extend LowerFile = tolower(FileName)
| extend
    SuspiciousPath = FolderPath has_any (@"\Downloads\", @"\Desktop\", @"\Temp\", @"\AppData\", @"\Public\", @"\ProgramData\"),
    IsHighAbuseTool = LowerFile in~ (HighAbuseTools),
    IsPortableExec = not(FolderPath has_any (@"\Program Files\", @"\Program Files (x86)\"))
| extend Severity = case(
    IsHighAbuseTool and SuspiciousPath, "🔴 Critical",
    IsHighAbuseTool or (SuspiciousPath and IsPortableExec), "🟠 High",
    SuspiciousPath or IsPortableExec, "🟡 Medium",
    "🟢 Low"
)
| summarize
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    Executions = count(),
    Paths = make_set(FolderPath, 5),
    CommandLines = make_set(ProcessCommandLine, 3)
    by Severity, AccountName, DeviceName, FileName, SuspiciousPath, IsHighAbuseTool, IsPortableExec
| project
    FirstSeen,
    Severity,
    Executions,
    DeviceName,
    AccountName,
    FileName,
    IsHighAbuseTool,
    SuspiciousPath,
    IsPortableExec,
    Paths,
    CommandLines,
    LastSeen
| sort by Severity asc, Executions desc
```
