# 🌐 Network Connection & DNS Timeline

**Reconstructs every network connection and DNS query on a device — including resolutions that succeeded even when the connection didn't.**

---

## 🎯 Purpose

Network activity is where an attacker's infrastructure gets exposed. C2 beacons, exfiltration destinations, second-stage payload servers — they all leave traces in connection logs. But relying on `DeviceNetworkEvents` alone misses a critical class of evidence: **DNS resolutions that happened even when the connection itself was blocked**.


This query unions both sources — real connections and DNS lookups — into a single timeline, giving you the complete network intent picture for the device.

---

## 🔍 How it works

| Step | Logic |
| --- | --- |
| 1️⃣ | Pull `DeviceNetworkEvents` for the target device and window — real connection attempts |
| 2️⃣ | Pull `DeviceEvents` filtered to `DnsQueryResponse`, `ConnectionFailed`, and `InboundConnectionAccepted` |
| 3️⃣ | Parse `AdditionalFields` from `DeviceEvents` to extract the queried DNS name |
| 4️⃣ | Tag `IsExternal` when the remote IP is public |
| 5️⃣ | Coalesce `Destination` from URL → IP → DNS name for readable output |
| 6️⃣ | Union both streams and normalize the schema |
| 7️⃣ | Sort ascending — connection sequence reads top to bottom |

---

## ⚖️ Risk signals surfaced

- **DNS query with no matching connection** — resolution succeeded but connection failed or was blocked; C2 domain contacted regardless
- **Raw IP destination with no DNS lookup** — connection skipped DNS entirely, common in malware using hardcoded IPs
- **Uncommon `RemotePort`** — non-standard ports (4444, 8080, 9001, high ephemeral) on external destinations
- **`Account` mismatch** — network activity under `SYSTEM` or a service account when a user should be the initiator
- **`ByProcess` is a script host or LOLBin** — `powershell.exe`, `mshta.exe`, `certutil.exe`, `bitsadmin.exe` making outbound connections
- **Sustained periodic connections** — regular beaconing intervals to the same destination, classic C2 pattern
- **`InboundConnectionAccepted` from external IP** — the device is receiving connections from outside, worth investigating why

---

## 🔍 KQL

```kql
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

---

## 📚 Reference

MITRE ATT&CK: T1071 (Application Layer Protocol), T1071.004 (DNS), T1090 (Proxy), T1571 (Non-Standard Port), T1568 (Dynamic Resolution), T1041 (Exfiltration Over C2 Channel), T1105 (Ingress Tool Transfer).
