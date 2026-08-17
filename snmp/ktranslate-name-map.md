# Native snmp_exporter names vs ktranslate tags

Mapping only — Alloy emits **native** names. ktranslate `kentik_snmp_*` stays on the existing poller.

| Native metric | ktranslate `tag` | ktranslate Prom name |
|---------------|------------------|----------------------|
| `mpCpuStatsUtil1MinuteRev` | `CPU` | `kentik_snmp_CPU` |
| `totalMemoryStats` | `MemoryTotal` | `kentik_snmp_MemoryTotal` |
| `memoryFreeStats` | `MemoryFree` | `kentik_snmp_MemoryFree` |
| `hwGlobalHealthStatus` | `—` | `—` |
| `lenovoEnvMibPowerSupplyState` | `—` | `—` |
| `lenovoEnvMibFanState` | `—` | `—` |
| `lenovoEnvMibFanSpeedRPM` | `FanRPM` | `kentik_snmp_FanRPM` |
| `lenovoEnvMibFanSpeedPercent` | `FanPercent` | `kentik_snmp_FanPercent` |
| `lenovoEnvMibTempSensorState` | `—` | `—` |
| `lenovoEnvMibTempSensorTemperature` | `Temperature` | `kentik_snmp_Temperature` |
| `lenovoEnvMIBTempSensorWarning` | `TempWarningThreshold` | `kentik_snmp_TempWarningThreshold` |
| `sgiCpuUsage` | `CPU` | `kentik_snmp_CPU` |
| `sgiKbMemoryUsed` | `MemoryUsed` | `kentik_snmp_MemoryUsed` |
| `sgiKbMemoryAvailable` | `MemoryFree` | `kentik_snmp_MemoryFree` |
| `tmnxHwOperState` | `—` | `—` |
| `tmnxHwTemperature` | `Temperature` | `kentik_snmp_Temperature` |
| `tmnxPhysChassisFanOperStatus` | `—` | `—` |
| `tmnxPhysChassisPMOutputStatus` | `—` | `—` |
| `tBgpPeerNgConnState` | `—` | `—` |
| `tBgpPeerNgOperStatus` | `—` | `—` |
| `tBgpPeerNgOperActivePrefixes` | `—` | `—` |
| `tBgpPeerNgOperFlaps` | `—` | `—` |
| `tBgpPeerNgOperReceivedPrefixes` | `—` | `—` |
| `tBgpPeerNgOperSentPrefixes` | `—` | `—` |
| `tBgpPeerNgOperEvpnActivePfxs` | `—` | `—` |
