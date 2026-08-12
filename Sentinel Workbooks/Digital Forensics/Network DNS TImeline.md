
```
// ============================================================
// FORENSICS: Network Connection & DNS Timeline
// ============================================================
// Every connection plus every DNS query. DNS matters because resolution
// often succeeds and is logged even when the connection itself was blocked,
// so it can be the only evidence a C2 domain was contacted.
// PARAMETERS: {DeviceName}, {TimeRange}
// ============================================================
let TargetDevice = "{DeviceName}";
union isfuzzy=true
(
    DeviceNetworkEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | extend
        EventKind = "Connection",
        IsExternal = iff(RemoteIPType == "Public", "YES", ""),
        Destination = coalesce(RemoteUrl, RemoteIP, "")
    | project
        TimeGenerated, DeviceName, EventKind,
        Action = ActionType,
        Destination,
        RemoteIP,
        RemotePort = tostring(RemotePort),
        RemoteUrl,
        IsExternal,
        Protocol,
        LocalIP,
        LocalPort = tostring(LocalPort),
        Account = InitiatingProcessAccountName,
        ByProcess = InitiatingProcessFileName,
        ByProcessCmd = InitiatingProcessCommandLine,
        SHA256 = InitiatingProcessSHA256
),
(
    DeviceEvents
    | where TimeGenerated {TimeRange}
    | where isempty(TargetDevice) or DeviceName has TargetDevice
    | where ActionType in ("DnsQueryResponse", "ConnectionFailed", "InboundConnectionAccepted")
    | extend
        Fields = parse_json(AdditionalFields),
        EventKind = "DNS / Conn Event"
    | project
        TimeGenerated, DeviceName, EventKind,
        Action = ActionType,
        Destination = coalesce(tostring(Fields.DnsQueryString), RemoteUrl, RemoteIP, ""),
        RemoteIP,
        RemotePort = tostring(RemotePort),
        RemoteUrl,
        IsExternal = iff(RemoteIPType == "Public", "YES", ""),
        Protocol = "",
        LocalIP,
        LocalPort = "",
        Account = InitiatingProcessAccountName,
        ByProcess = InitiatingProcessFileName,
        ByProcessCmd = InitiatingProcessCommandLine,
        SHA256 = InitiatingProcessSHA256
)
| sort by TimeGenerated asc
```
