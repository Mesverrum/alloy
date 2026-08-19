---
canonical: https://grafana.com/docs/alloy/latest/reference/components/loki/loki.source.snmptrap/
aliases:
  - ../loki.source.snmptrap/ # /docs/alloy/latest/reference/components/loki/loki.source.snmptrap/
description: Learn about loki.source.snmptrap
labels:
  stage: experimental
  products:
    - oss
title: loki.source.snmptrap
---

# `loki.source.snmptrap`

{{< docs/shared lookup="stability/experimental.md" source="alloy" version="<ALLOY_VERSION>" >}}

`loki.source.snmptrap` listens for SNMP traps and informs over UDP and forwards
them to other `loki.*` components as structured JSON log entries.

It is a logging source (peer of [`loki.source.syslog`](loki.source.syslog.md)),
not a metrics scrape. MIB name enrichment is best-effort via [gosmi](https://github.com/sleepinggenius2/gosmi);
unresolved OIDs stay numeric so receive still works without a dictionary.

You can run multiple `loki.source.snmptrap` components with different labels
and listen addresses.

## Usage

```alloy
loki.source.snmptrap "<LABEL>" {
  listen_address = "0.0.0.0:1620"
  forward_to     = <RECEIVER_LIST>
}
```

## Arguments

| Name                | Type                 | Description | Default | Required |
| ------------------- | -------------------- | ----------- | ------- | -------- |
| `forward_to`        | `list(LogsReceiver)` | Receivers to send log entries to. | | yes |
| `listen_address`    | `string`             | UDP host:port to listen on. | `"0.0.0.0:1620"` | no |
| `communities`       | `list(string)`       | Community allowlist for SNMPv1/v2c. Omit or empty to **accept all**. | | no |
| `include_community` | `bool`               | Put the community string on the JSON body and a `community` label. Off by default (secret-adjacent). | `false` | no |
| `drop_undefined`    | `bool`               | Drop traps whose trap OID is not in the MIB dictionary. Default is fail-open. | `false` | no |
| `mib_paths`         | `list(string)`       | Directories of curated MIB files for gosmi name lookup. | | no |
| `labels`            | `map(string)`        | Extra labels to attach before relabeling. | | no |
| `relabel_rules`     | `RelabelRules`       | Relabel rules applied to each entry. | `{}` | no |
| `targets`           | `list(map(string))`  | Optional discovery catalog (typically [`discovery.snmp`](../../discovery/discovery.snmp.md) `.targets`). Joins UDP source (then SNMPv1 `agent_address`) to `device_name`. | | no |

{{< admonition type="note" >}}
UDP 162 is privileged. The default **1620** matches the lab container mapping
(`162:1620/udp`). To bind `:162`, grant `CAP_NET_BIND_SERVICE` or DNAT 162→1620.
{{< /admonition >}}

Empty `communities` means **accept every v1/v2c community**. That matches how
most operators run trap receivers. If you set `communities`, only listed values
are accepted; others increment `loki_source_snmptrap_dropped_total{reason="community"}`.

The `relabel_rules` argument accepts the `rules` export from
[`loki.relabel`](loki.relabel.md). Incoming messages have these internal labels:

- `__snmptrap_source` — UDP source IP
- `__snmptrap_oid` — numeric trap OID (`snmpTrapOID.0`, or RFC 2576 mapping for v1)
- `__snmptrap_name` — textual name when gosmi resolves it, else the numeric OID
- `__snmptrap_mib` — MIB module name when resolved
- `__snmptrap_version` — `1`, `2c`, or `3`
- `__snmptrap_pdu` — `trap` or `inform`
- `__snmptrap_engine_id` — SNMPv3 engine ID (hex), when present
- `__snmptrap_context` — SNMPv3 context name, when present

When `targets` is set, a matching catalog IP stamps `device_name` (and
`snmp_group` when present) as **kept** labels and puts `device_name` on the
JSON body. Collapsed extra IPs are on `snmp_aliases` so a trap from a
non-scraped address still joins. Catalog refreshes do **not** restart the UDP
listener — only `listen_address`, `communities`, `mib_paths`, or `v3` do.

`loki_source_snmptrap_joined_total` / `unjoined_total` increment only while a
catalog is set.

All labels starting with `__` are removed before forwarding. Relabel them to
keep them:

```alloy
loki.relabel "traps" {
  rule {
    source_labels = ["__snmptrap_name"]
    target_label  = "trap"
  }
  rule {
    source_labels = ["__snmptrap_source"]
    target_label  = "source"
  }
}

loki.source.snmptrap "lab" {
  listen_address = "0.0.0.0:1620"
  relabel_rules  = loki.relabel.traps.rules
  forward_to     = [loki.write.gc.receiver]
}
```

Each log line is compact JSON, for example:

```json
{
  "time": "2026-08-18T19:00:00Z",
  "source": "172.20.20.2",
  "device_name": "spine1",
  "version": "2c",
  "pdu_type": "trap",
  "trap_oid": "1.3.6.1.6.3.1.1.5.1",
  "trap_name": "SNMPv2-MIB::coldStart",
  "mib": "SNMPv2-MIB",
  "varbinds": [
    {"oid": "1.3.6.1.2.1.1.3.0", "name": "SNMPv2-MIB::sysUpTime.0", "type": "TimeTicks", "value": 1234}
  ]
}
```

Informs are accepted and answered; the log `pdu_type` is `inform`.

Mount a **small curated** MIB set on `mib_paths`. Distro or vendor mega-trees
can hang or fail gosmi — do not dump `/usr/share/snmp/mibs` wholesale.

`drop_undefined` requires a loaded dictionary. With no `mib_paths` every trap
looks unresolved and would be dropped.

## Blocks

### `v3`

Optional SNMPv3 USM user. When this block is set, the listener is v3-only
(v1/v2c packets are not decoded). gosnmp v3 trap receive is still evolving.

| Name             | Type     | Description | Default | Required |
| ---------------- | -------- | ----------- | ------- | -------- |
| `user`           | `string` | USM user name. | | yes |
| `security_level` | `string` | `noAuthNoPriv`, `authNoPriv`, or `authPriv`. | `"noAuthNoPriv"` | no |
| `auth_protocol`  | `string` | `MD5`, `SHA`, `SHA224`, `SHA256`, `SHA384`, `SHA512`. | | no |
| `auth_password`  | `secret` | Authentication passphrase. | | no |
| `priv_protocol`  | `string` | `DES`, `AES`, `AES192`, `AES192C`, `AES256`, `AES256C`. | | no |
| `priv_password`  | `secret` | Privacy passphrase. | | no |

## Component health

`loki.source.snmptrap` is reported unhealthy only when given an invalid
configuration or when the UDP bind fails.

## Debug information

`loki.source.snmptrap` doesn't expose any component-specific debug information.

## Debug metrics

* `loki_source_snmptrap_received_total{pdu}` (counter): Packets the UDP listener handed to the handler. `pdu` is `trap` or `inform`.
* `loki_source_snmptrap_entries_total` (counter): Traps/informs forwarded.
* `loki_source_snmptrap_joined_total` (counter): Traps whose source IP matched a `targets` identity. Only increments when `targets` is set.
* `loki_source_snmptrap_unjoined_total` (counter): Traps received while `targets` was set but the source IP was unknown.
* `loki_source_snmptrap_errors_total` (counter): Decode or marshal failures.
* `loki_source_snmptrap_dropped_total{reason}` (counter): Drops.
  `reason` is `queue_full`, `undefined`, or `community`.
* `loki_source_snmptrap_queue_length` (gauge): Outbound log channel depth.
* `loki_source_snmptrap_queue_capacity` (gauge): Channel capacity (1024). Backlog is `queue_length / queue_capacity`.
* `loki_source_snmptrap_handle_duration_seconds` (histogram): Decode + enqueue time.

The UDP receive path never blocks the listen loop: a full outbound queue drops
the trap and increments `queue_full`. Watch `queue_length` before drops start.

## Example

```alloy
discovery.snmp "fabric" {
  snmp_config = "/etc/alloy/snmp-network.yml"

  group {
    name  = "hq"
    cidrs = ["172.20.20.0/24"]
    auths = ["public_v2"]
  }
}

loki.relabel "traps" {
  rule {
    source_labels = ["__snmptrap_name"]
    target_label  = "trap"
  }
  rule {
    source_labels = ["__snmptrap_source"]
    target_label  = "source"
  }
  rule {
    source_labels = ["__snmptrap_version"]
    target_label  = "snmp_version"
  }
}

loki.source.snmptrap "fabric" {
  listen_address = "0.0.0.0:1620"
  mib_paths      = ["/etc/alloy/mibs"]
  targets        = discovery.snmp.fabric.targets
  labels         = { job = "snmptrap", site = "hq" }
  relabel_rules  = loki.relabel.traps.rules
  forward_to     = [loki.write.gc.receiver]
}

loki.write "gc" {
  endpoint {
    url = "https://logs-prod.grafana.net/loki/api/v1/push"
  }
}
```

Query in Loki:

```logql
{job="snmptrap"} | json | trap_name != ""
{job="snmptrap", device_name="spine1"}
```

<!-- START GENERATED COMPATIBLE COMPONENTS -->

## Compatible components

`loki.source.snmptrap` can accept arguments from the following components:

- Components that export [Loki `LogsReceiver`](../../../compatibility/#loki-logsreceiver-exporters)

{{< admonition type="note" >}}
Connecting some components may not be sensible or components may require further configuration to make the connection work correctly.
Refer to the linked documentation for more details.
{{< /admonition >}}

<!-- END GENERATED COMPATIBLE COMPONENTS -->
