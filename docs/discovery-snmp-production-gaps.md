# `discovery.snmp` — production gaps (circle back)

**Status:** experimental fork capability. Component now follows Alloy norms for
logging, health, metrics, Live Debugging, and reference docs. Still
**not** GA — needs Alloy-team review, grafana.com publish, and a few product
gaps below.

## Done (PR bar)

| Area | What landed |
|------|-------------|
| **Logging** | Library takes `ScanParams.Logger *slog.Logger` (nil → `slog.Default()`). Scan summary is `Info`; per-device finds, claimed skips, and probe errors are `Debug`. |
| **Health** | `component.HealthComponent`: Unknown → Healthy/Unhealthy. Failed scans keep last targets. Overlap skip does not change health. |
| **Live debugging** | Publishes the current target list on each successful scan (`discovery.process` pattern). |
| **Metrics** | `discovery_snmp_scans_total`, `scan_failures_total`, `scan_skipped_total`, `scan_duration_seconds`, `devices`, `targets`, `sweep_addresses`, `ping_up`, `dropped_total`, `probe_errors_total` on `opts.Registerer`. |
| **Config tests** | `syntax.Unmarshal` (including `ping = false`), `Validate` ranges, failed-scan health, overlap skip. |
| **Docs** | `docs/sources/reference/components/discovery/discovery.snmp.md` — `canonical` / `aliases`, CAP_NET_RAW / bool footgun, exported labels (`snmp_aliases`), health, debug metrics, troubleshooting, compatible components. |
| **Identity join (traps / syslog / flow)** | Hostname collapse keeps loser IPs as `snmp_aliases`. Shared `devicejoin` indexes `address`, aliases, and `device_name`. `otelcol.receiver.snmptrap`, `otelcol.receiver.syslog`, and `otelcol.receiver.netflow` optional `targets` stamp `device_name` / `snmp_group` at receive time without restarting listeners on catalog refresh. Flow also stamps `src_device` / `dst_device` when those IPs are in the catalog. |
| **Concurrency** | `TryLock` overlap skip (same as the CLI). |
| **Validate** | `concurrency`, `timeout`, `ping_timeout` > 0; `port` 1–65535; `retries`/`misses` ≥ 0. Missing files fail the **scan** (health), not Validate — Fleet may mount them after start. |

## Still open (not blocking a first PR)

| Area | Notes |
|------|--------|
| **Stability** | Remains `StabilityExperimental` until Alloy review. |
| **Integration tests** | No fake SNMP/ICMP end-to-end. Library tests cover CIDR/crawl/fingerprint; component tests cover config + failure/overlap paths. |
| **Image** | Lab still uses `Dockerfile.network-src` / `build-alloy-bin-overlay.sh`. Official `make alloy` is the PR path. |
| **CLI** | Image CLI is `github.com/Mesverrum/snmp-sd/cmd/snmp-discovery`. Do not vendor convert / init / walk-pick into this tree. |
| **File Validate** | Intentionally not requiring files exist at load time. |

## Related code

- Component: `internal/component/discovery/snmp/`
- Library: `github.com/Mesverrum/snmp-sd/snmpdiscovery`
- Join: `internal/component/common/devicejoin/` → `otelcol.receiver.snmptrap` / `otelcol.receiver.syslog` / `otelcol.receiver.netflow` `targets`
- CLI: built from `github.com/Mesverrum/snmp-sd/cmd/snmp-discovery`
- Docs: `docs/sources/reference/components/discovery/discovery.snmp.md`
- Lab: `ALLOY_NETWORK_FROM_SOURCE=1` → `local/scripts/build-alloy-bin-overlay.sh`
