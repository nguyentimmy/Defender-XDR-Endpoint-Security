## 💓 Defender Health

**The blind-spot map: onboarded devices whose sensor isn't reporting healthy.**

A device with an inactive or misconfigured sensor generates no detections — which looks identical to a clean device. This panel closes that gap.

- Filters to devices marked Onboarded whose `SensorHealthState` isn't Active
- Severity: Inactive or Misconfigured = Critical; ImpairedCommunication = High

**Note:** an empty result is the healthy state — it means every onboarded device is reporting.

**Placement:** worth putting first on the dashboard, since it tells you how much to trust everything below it.

---

## Known limitation

Secure-configuration posture — real-time protection off, tamper protection disabled, stale signatures — lives in the `DeviceTvm*` tables, which are **Defender XDR only** and are not streamed to Log Analytics by the standard connector. Those queries return no results in a Sentinel workbook even though they work in Advanced Hunting.

| Works in a Sentinel workbook | Advanced Hunting only |
| --- | --- |
| `DeviceInfo`, `DeviceEvents`, `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`, `DeviceImageLoadEvents` | All `DeviceTvm*` tables |

The Defender Health panel uses `DeviceInfo` for this reason — it covers the most important blind spot (sensors not reporting) and works in both backends. Run configuration-posture queries Defender-side.
```
// ============================================================
// Defender Health - Sensor Not Reporting (Sentinel-compatible)
// ============================================================
// Blind-spot map: onboarded devices whose Defender sensor isn't healthy.
// Uses DeviceInfo, which IS exported to Log Analytics - unlike the
// DeviceTvm* tables, which are Defender-XDR-only.
// NOTE: an empty result is the healthy state.
// ============================================================
let LookupTime = 7d;
DeviceInfo
| where TimeGenerated > ago(LookupTime)
| summarize arg_max(TimeGenerated, OnboardingStatus, SensorHealthState) by DeviceName, DeviceId
| where OnboardingStatus == "Onboarded"
| where SensorHealthState !in~ ("Active", "")
| extend Severity = case(
    SensorHealthState has_any ("Inactive", "Misconfigured"), "🔴 Critical",
    SensorHealthState has "ImpairedCommunication", "🟠 High",
    "🟡 Medium"
)
| project
    LastSeen = TimeGenerated,
    Severity,
    DeviceName,
    SensorHealthState,
    OnboardingStatus,
    DeviceId
| sort by Severity asc, LastSeen asc
```
