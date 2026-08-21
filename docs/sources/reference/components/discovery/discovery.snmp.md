---
canonical: https://grafana.com/docs/alloy/latest/reference/components/discovery/discovery.snmp/
aliases:
  - ../discovery.snmp/ # /docs/alloy/latest/reference/components/discovery.snmp/
description: Learn about discovery.snmp
labels:
  stage: experimental
  products:
    - oss
title: discovery.snmp
---

# `discovery.snmp`

{{< docs/shared lookup="stability/experimental.md" source="alloy" version="<ALLOY_VERSION>" >}}

`discovery.snmp` discovers SNMP scrape targets by probing CIDRs and optionally
crawling LLDP/CDP neighbors. It is a Prometheus-shaped **Discoverer**: named
`auth` values and fingerprinter-selected `module` lists. Community strings and
SNMPv3 secrets never appear on labels.

Use it with stock [`prometheus.exporter.snmp`][prometheus.exporter.snmp].
Secrets stay in the `auths:` section of `snmp.yml`.

[prometheus.exporter.snmp]: ../../prometheus/prometheus.exporter.snmp/

{{< admonition type="note" >}}
ICMP pre-filtering (`ping = true`, the default) needs `CAP_NET_RAW` (or
equivalent) so Alloy can send echo requests. In containers without that
capability, set `ping = false` or every sweep looks empty.

Alloy bool defaults apply only when the attribute is omitted. Write
`ping = false` explicitly. A missing `ping` is **not** the same as `false`.
{{< /admonition >}}

## Usage

```alloy
discovery.snmp "<LABEL>" {
  group {
    name  = "hq"
    cidrs = ["172.20.20.0/24"]
    auths = ["public_v2"]
  }
}
```

## Arguments

You can use the following arguments with `discovery.snmp`:

| Name               | Type           | Description | Default | Required |
| ------------------ | -------------- | ----------- | ------- | -------- |
| `snmp_config`      | `string`       | Path to snmp_exporter `snmp.yml` (`auths` + modules). Omit to use the image library. | `"/etc/alloy/snmp-network.yml"` | no |
| `config_path`      | `string`       | Path to discovery groups YAML. Preferred over inline `group` blocks for the group list. | | no |
| `overrides_path`   | `string`       | Optional overrides YAML merged into the config. | | no |
| `fingerprinters`   | `string`       | Path to fingerprinters YAML. | `"/etc/alloy/fingerprinters.yml"` | no |
| `fingerprinter`    | `string`       | Default fingerprinter name when a group omits one. | `"network"` | no |
| `tier`             | `string`       | `hot`, `cold`, `topology`, or `all`. | `"all"` | no |
| `refresh_interval` | `duration`     | Rescan period. Prefer hours–days in production. | `"15m"` | no |
| `concurrency`      | `number`       | Parallel SNMP probes. Must be `> 0`. | `8` | no |
| `timeout`          | `duration`     | Per-auth SNMP timeout. Must be `> 0`. | `"2s"` | no |
| `retries`          | `number`       | SNMP retries per auth. | `0` | no |
| `port`             | `number`       | Default SNMP UDP port (`1`–`65535`). | `161` | no |
| `ping`             | `bool`         | ICMP-filter CIDR sweeps before SNMP. | `true` | no |
| `ping_timeout`     | `duration`     | ICMP wait after the last echo. Must be `> 0`. | `"400ms"` | no |
| `misses`           | `number`       | Drop a catalog target after this many silent cycles (`0` = never). | `3` | no |
| `state_path`       | `string`       | Persist miss counters across restarts. | | no |
| `allow_large`              | `bool`         | Allow CIDR sweeps wider than `/22`. | `false` | no |
| `allow_duplicate_sysname`  | `bool`         | Keep every SNMP address when several share a `sysName` (cloned IoT hostnames). Default collapses them: one identity, **lowest IP** wins. | `false` | no |

Provide `config_path` **or** at least one `group` block.

Missing `snmp_config` / `fingerprinters` files are not rejected at load time
(Fleet may mount them later). A scan that cannot open them is reported
unhealthy and keeps the last exported targets.

## Blocks

You can use the following blocks with `discovery.snmp`:

### `group`

CIDR-scoped discovery group. Never put a community string here — name an auth from `snmp.yml`.

| Name            | Type           | Description | Default | Required |
| --------------- | -------------- | ----------- | ------- | -------- |
| `name`          | `string`       | Group name (also the `snmp_group` label). | | yes |
| `auths`         | `list(string)` | Auth names from `snmp.yml`. | | yes |
| `cidrs`         | `list(string)` | Networks to sweep. | | no* |
| `seeds`         | `list(string)` | Seed IPs for crawl mode. | | no |
| `exclude`       | `list(string)` | CIDRs/IPs to skip. | | no |
| `fingerprinter` | `string`       | Override default fingerprinter. | | no |
| `port`          | `number`       | SNMP port for this group. | | no |
| `mode`          | `string`       | `sweep`, `crawl`, or `both`. | `"both"` | no |
| `ping`          | `bool`         | Per-group ICMP filter override. | | no |
| `allow_large`   | `bool`         | Allow wide CIDRs for this group. | | no |

\*At least one of `cidrs` / `seeds` depending on `mode` (validated by the discovery library).

### `override`

Operator pin or ignore by SNMP address.

| Name              | Type     | Description |
| ----------------- | -------- | ----------- |
| `address`         | `string` | Device SNMP IP. |
| `ignore`          | `bool`   | Drop from catalog. |
| `name`            | `string` | Force target name. |
| `module`          | `string` | Legacy full module chain (partitioned into tiers). |
| `module_hot`      | `string` | Hot-tier modules. |
| `module_cold`     | `string` | Cold-tier modules. |
| `module_topology` | `string` | Topology-tier modules. |
| `auth`            | `string` | Force auth name. |

## Exported fields

The following fields are exported and can be referenced by other components:

| Name      | Type                | Description |
| --------- | ------------------- | ----------- |
| `targets` | `list(map(string))` | Targets for `prometheus.exporter.snmp`. |

Each target includes the following labels:

| Label          | Description |
| -------------- | ----------- |
| `name`         | Target name derived from `sysName` (or the address). |
| `address`      | SNMP address (canonical IP). |
| `module`       | Comma-separated snmp_exporter modules for this `snmp_tier`. |
| `auth`         | Named auth from `snmp.yml`. Never a community string. |
| `device_name`  | Device identity from `sysName`. Same hostname on multiple IPs is one identity unless `allow_duplicate_sysname`. Pass `.targets` to [`loki.source.snmptrap`](../loki/loki.source.snmptrap.md) to stamp this on traps. |
| `snmp_tier`    | `hot`, `cold`, or `topology`. |
| `sysObjectID`  | Present when the probe returned one. |
| `snmp_group`   | Discovery group name. |
| `snmp_aliases` | Extra IPs collapsed into this identity (comma-separated). Not scraped; used so traps from those addresses still join. |

Community strings are never exported.

With `tier = "all"` (default), one device becomes up to three targets — one per
non-empty tier — so you can scrape hot/cold/topology on different intervals.

## Component health

`discovery.snmp` reports:

* **Unknown** until the first scan finishes.
* **Healthy** after a successful scan, with a message of the form
  `discovered N devices, M targets`.
* **Unhealthy** when configuration is invalid or a scan fails (missing files,
  unreadable YAML, CIDR expansion errors).

Failed scans keep the last exported targets. A tick that arrives while a
previous scan is still running is skipped (see `discovery_snmp_scan_skipped_total`)
and does not change health.

## Debug information

`discovery.snmp` does not expose static debug information.

When [Live Debugging][livedebugging] is enabled, each successful scan publishes
the current target list.

[livedebugging]: ../../../troubleshoot/debug/#live-debugging-page

## Debug metrics

**Scan / pressure**

* `discovery_snmp_scans_total` (counter): Scans that ran to completion (success or failure).
* `discovery_snmp_scan_failures_total` (counter): Scans that failed.
* `discovery_snmp_scan_skipped_total` (counter): Ticks skipped because a scan was already running.
* `discovery_snmp_scan_duration_seconds` (histogram): Duration of completed successful scans.
* `discovery_snmp_scan_in_progress` (gauge): `1` while a scan is running. Combined with skips, this is the “can’t keep up with `refresh_interval`” signal.

**Last successful scan**

* `discovery_snmp_devices` / `discovery_snmp_targets` (gauges): Catalog size and exported targets.
* `discovery_snmp_sweep_addresses` / `discovery_snmp_ping_up` / `discovery_snmp_ping_dead` (gauges): CIDR size, ICMP-alive, ICMP-dropped (`sweep - ping_up`).
* `discovery_snmp_probe_successes` / `discovery_snmp_probe_errors` (gauges): Identity probes that worked / failed.
* `discovery_snmp_dedupes` (gauge): Extra IPs folded into another `sysName` (lowest IP kept).
* `discovery_snmp_dropped_total` (counter): Devices dropped after consecutive silent cycles.
* `discovery_snmp_dedupes_total` (counter): Running total of folded addresses.

**Per-probe (identity Get of sysObjectID/sysName/sysDescr)**

* `discovery_snmp_probes_total{result}` (counter): `success` or `error`.
* `discovery_snmp_probe_errors_total{reason}` (counter): `timeout`, `refused`, `connect`, `empty`, `no_sys`, `no_auth`, `other`.
* `discovery_snmp_probe_duration_seconds` (histogram): One address, including auth walk and retries.
* `discovery_snmp_probes_in_flight` (gauge): Live probe concurrency (compare to `concurrency`).
* `discovery_snmp_first_auth_success_total` (counter): First named auth worked.
* `discovery_snmp_auth_fallback_total` (counter): A later auth worked after an earlier one failed.
* `discovery_snmp_auth_failures_total` (counter): Per-auth attempts that failed.
* `discovery_snmp_probe_retries_total` (counter): Extra SNMP Gets after the first try for an auth.

Device **walk** pressure (CPU/interface tables) is on stock `prometheus.exporter.snmp`: `snmp_request_in_flight`, `snmp_packet_retries_total`, `snmp_scrape_duration_seconds`, `up`.

Enable debug logs on the component to see per-device finds, claimed-address
skips, and individual probe errors.

## Troubleshooting

| Symptom | Likely cause | What to do |
|---------|--------------|------------|
| Component unhealthy; `scan failed` mentions fingerprinters or `snmp.yml` | File not mounted yet, or wrong path | Confirm `snmp_config` / `fingerprinters` exist in the Alloy container. Fleet pipelines often mount them after start — the next successful scan recovers. |
| Sweep finds nothing; ICMP errors in debug logs | `ping = true` without `CAP_NET_RAW` | Set `ping = false`, or add `CAP_NET_RAW` / run with sufficient privileges. |
| Devices flap in and out of the catalog | `misses` too low for a slow or lossy network | Raise `misses`, or set `misses = 0` and persist `state_path`. |
| CIDR rejected as too wide | Default `/22` cap | Set `allow_large = true` on the component or the `group`. |
| One router, two IPs, only one scrape target | Same `sysName` collapsed (lowest IP scraped; others on `snmp_aliases`) | Expected. Traps from the alias IP still join `device_name`. Set `allow_duplicate_sysname = true` only if those IPs are really different devices. |
| Many IoT boxes share `sysName` and only one appears | Hostname collapse | Set `allow_duplicate_sysname = true`. |
| Community string on a label | Misconfigured exporter, not this Discoverer | `discovery.snmp` only exports the **auth name**. Keep secrets in `snmp.yml` `auths:`. |

## Same `sysName`, multiple IPs

Within one scan, targets that share a `sysName` (compared case-insensitively after
stripping a DNS suffix) become **one identity**. The lowest address wins
(`netip.Addr` order: IPv4 before IPv6, then numeric — so `10.0.0.2` beats
`10.0.0.10`). The extra addresses are dropped from the catalog immediately so
they do not linger on the miss counter.

Empty `sysName` (identity is the IP itself) is never collapsed.

This is per discovery job, not a global CMDB merge. Extra IPs stay on
`snmp_aliases` so [`loki.source.snmptrap`](../loki/loki.source.snmptrap.md)
(`targets = discovery.snmp.<label>.targets`) can join a trap from the
non-scraped address to the same `device_name`.

For fleets that clone hostnames, set `allow_duplicate_sysname = true`. Then
`name` is uniquified with `-<address>` and `device_name` stays the shared
hostname.

## Example (Fleet-friendly staggered scrapes)

```alloy
discovery.snmp "fabric" {
  refresh_interval = "15m"
  state_path       = "/var/lib/alloy/snmp-discovery.state.json"

  group {
    name  = "hq"
    cidrs = ["172.20.20.0/24"]
    auths = ["public_v2"]
  }
}

discovery.relabel "snmp_hot" {
  targets = discovery.snmp.fabric.targets
  rule {
    source_labels = ["snmp_tier"]
    regex         = "hot"
    action        = "keep"
  }
}

discovery.relabel "snmp_cold" {
  targets = discovery.snmp.fabric.targets
  rule {
    source_labels = ["snmp_tier"]
    regex         = "cold"
    action        = "keep"
  }
}

prometheus.exporter.snmp "hot" {
  targets = discovery.relabel.snmp_hot.output
}

prometheus.exporter.snmp "cold" {
  targets = discovery.relabel.snmp_cold.output
}

prometheus.scrape "snmp_hot" {
  targets         = prometheus.exporter.snmp.hot.targets
  scrape_interval = "60s"
  forward_to      = [prometheus.relabel.default.receiver]
}

prometheus.scrape "snmp_cold" {
  targets         = prometheus.exporter.snmp.cold.targets
  scrape_interval = "5m"
  forward_to      = [prometheus.relabel.default.receiver]
}
```

Pin a single tier on the discoverer instead of filtering with `discovery.relabel`:

```alloy
discovery.snmp "hot" {
  tier = "hot"

  group {
    name  = "hq"
    cidrs = ["172.20.20.0/24"]
    auths = ["public_v2"]
  }
}

prometheus.exporter.snmp "fabric_hot" {
  targets = discovery.snmp.hot.targets
}
```

<!-- START GENERATED COMPATIBLE COMPONENTS -->

## Compatible components

`discovery.snmp` has exports that can be consumed by the following components:

- Components that consume [Targets](../../../compatibility/#targets-consumers)

{{< admonition type="note" >}}
Connecting some components may not be sensible or components may require further configuration to make the connection work correctly.
Refer to the linked documentation for more details.
{{< /admonition >}}

<!-- END GENERATED COMPATIBLE COMPONENTS -->
