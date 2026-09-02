---
canonical: https://grafana.com/docs/alloy/latest/reference/components/otelcol/otelcol.receiver.snmptrap/
description: Learn about otelcol.receiver.snmptrap
labels:
  stage: experimental
  products:
    - oss
title: otelcol.receiver.snmptrap
---

# `otelcol.receiver.snmptrap`

{{< docs/shared lookup="stability/experimental.md" source="alloy" version="<ALLOY_VERSION>" >}}

`otelcol.receiver.snmptrap` listens for SNMP traps and informs over UDP and
forwards each PDU as an OpenTelemetry **log**. It is not a metrics scrape.

This component lives on the OTel path (peer of [`otelcol.receiver.netflow`][]),
not `loki.source.*`. MIB name enrichment is best-effort via [gosmi](https://github.com/sleepinggenius2/gosmi);
unresolved OIDs stay numeric so receive still works without a dictionary.

You can specify multiple `otelcol.receiver.snmptrap` components by giving them
different labels and listen addresses.

Each log record has:

* **Body** — compact JSON of the decoded trap (source, trap OID/name, varbinds)
* **Attributes** — `source`, `trap_oid`, `trap_name`, `trap_mib`, `snmp_version`,
  `pdu_type`, plus `device_name` / `snmp_group` when `targets` matches

When `targets` is set, a matching catalog IP (UDP source, then SNMPv1
`agent_address`, including `snmp_aliases`) stamps `device_name` on both the
attributes and the JSON body. Catalog refreshes do **not** restart the UDP
listener — only `listen_address`, `communities`, `mib_paths`, or `v3` do.

`otelcol_receiver_snmptrap_joined_total` / `unjoined_total` increment only while
a catalog is set.

## Usage

```alloy
otelcol.receiver.snmptrap "<LABEL>" {
  listen_address = "0.0.0.0:1620"

  output {
    logs = [...]
  }
}
```

## Arguments

You can use the following arguments with `otelcol.receiver.snmptrap`:

| Name                | Type                | Description | Default | Required |
| ------------------- | ------------------- | ----------- | ------- | -------- |
| `listen_address`    | `string`            | UDP host:port to listen on. | `"0.0.0.0:1620"` | no |
| `communities`       | `list(string)`      | Community allowlist for SNMPv1/v2c. Omit or empty to **accept all**. | | no |
| `include_community` | `bool`              | Put the community string on the JSON body and a `community` attribute. Off by default (secret-adjacent). | `false` | no |
| `drop_undefined`    | `bool`              | Drop traps whose trap OID is not in the MIB dictionary. Default is fail-open. | `false` | no |
| `mib_paths`         | `list(string)`      | Directories of curated MIB files for gosmi name lookup. Omit to use the image tree. Set `[]` to skip. | `["/etc/alloy/mibs"]` | no |
| `attributes`        | `map(string)`       | Extra attributes attached to every log record. | | no |
| `targets`           | `list(map(string))` | Optional discovery catalog (typically [`discovery.snmp`][] `.targets`). Joins UDP source (then SNMPv1 `agent_address`) to `device_name`. | | no |

{{< admonition type="note" >}}
UDP 162 is privileged. The default **1620** matches the lab container mapping
(`162:1620/udp`). To bind `:162`, grant `CAP_NET_BIND_SERVICE` or DNAT 162→1620.
{{< /admonition >}}

Empty `communities` means **accept every v1/v2c community**. That matches how
most operators run trap receivers. If you set `communities`, only listed values
are accepted; others increment `otelcol_receiver_snmptrap_dropped_total{reason="community"}`.

A missing default MIB directory is skipped (OIDs stay numeric). Distro or
vendor mega-trees can hang or fail gosmi — do not dump `/usr/share/snmp/mibs`
wholesale. Override `mib_paths` only for a custom tree; set `mib_paths = []`
to skip lookup.

`drop_undefined` requires a loaded dictionary. With an empty `mib_paths` every
trap looks unresolved and would be dropped.

## Blocks

You can use the following blocks with `otelcol.receiver.snmptrap`:

{{< docs/alloy-config >}}

| Block                            | Description                                                                | Required |
|----------------------------------|----------------------------------------------------------------------------|----------|
| [`output`][output]               | Configures where to send received telemetry data.                          | yes      |
| [`v3`][v3]                       | Optional SNMPv3 USM user. When set, the listener is v3-only.               | no       |
| [`debug_metrics`][debug_metrics] | Configures the metrics that this component generates to monitor its state. | no       |

[debug_metrics]: #debug_metrics
[output]: #output
[v3]: #v3

{{< /docs/alloy-config >}}

### `output`

{{< badge text="Required" >}}

{{< docs/shared lookup="reference/components/output-block-logs.md" source="alloy" version="<ALLOY_VERSION>" >}}

### `debug_metrics`

{{< docs/shared lookup="reference/components/otelcol-debug-metrics-block.md" source="alloy" version="<ALLOY_VERSION>" >}}

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

## Exported fields

`otelcol.receiver.snmptrap` doesn't export any fields.

## Component health

`otelcol.receiver.snmptrap` is reported unhealthy only when given an invalid
configuration or when the UDP bind fails.

## Debug information

`otelcol.receiver.snmptrap` doesn't expose any component-specific debug information.

## Debug metrics

* `otelcol_receiver_snmptrap_received_total{pdu}` (counter): Packets the UDP listener handed to the handler. `pdu` is `trap` or `inform`.
* `otelcol_receiver_snmptrap_entries_total` (counter): Traps/informs forwarded to the OTel pipeline.
* `otelcol_receiver_snmptrap_joined_total` (counter): Traps whose source IP matched a `targets` identity. Only increments when `targets` is set.
* `otelcol_receiver_snmptrap_unjoined_total` (counter): Traps received while `targets` was set but the source IP was unknown.
* `otelcol_receiver_snmptrap_errors_total` (counter): Decode, marshal, or consume failures.
* `otelcol_receiver_snmptrap_dropped_total{reason}` (counter): Drops.
  `reason` is `queue_full`, `undefined`, or `community`.
* `otelcol_receiver_snmptrap_queue_length` (gauge): Outbound log channel depth.
* `otelcol_receiver_snmptrap_queue_capacity` (gauge): Channel capacity (1024). Backlog is `queue_length / queue_capacity`.
* `otelcol_receiver_snmptrap_handle_duration_seconds` (histogram): Decode + enqueue time.

The UDP receive path never blocks the listen loop: a full outbound queue drops
the trap and increments `queue_full`.

## Example

```alloy
discovery.snmp "fabric" {
  group {
    name  = "hq"
    cidrs = ["172.20.20.0/24"]
    auths = ["public_v2"]
  }
}

otelcol.receiver.snmptrap "fabric" {
  targets    = discovery.snmp.fabric.targets
  attributes = {
    job = "snmptrap",
  }

  output {
    logs = [otelcol.processor.batch.default.input]
  }
}

otelcol.processor.batch "default" {
  output {
    logs = [otelcol.exporter.otlphttp.gc.input]
  }
}

otelcol.exporter.otlphttp "gc" {
  client {
    endpoint = sys.env("GC_OTLP_URL")
    auth     = otelcol.auth.basic.gc.handler
  }
}
```

Each log body is compact JSON, for example:

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

Query after OTLP export to Grafana Cloud (resource `service.name` is set by the
pipeline, not this component):

```logql
{service_name="alloy-snmptrap"}
{service_name="alloy-snmptrap", device_name="spine1"}
```

<!-- START GENERATED COMPATIBLE COMPONENTS -->

## Compatible components

`otelcol.receiver.snmptrap` can accept arguments from the following components:

- Components that export [OpenTelemetry `otelcol.Consumer`](../../../compatibility/#opentelemetry-otelcolconsumer-exporters)

{{< admonition type="note" >}}
Connecting some components may not be sensible or components may require further configuration to make the connection work correctly.
Refer to the linked documentation for more details.
{{< /admonition >}}

<!-- END GENERATED COMPATIBLE COMPONENTS -->

[`otelcol.receiver.netflow`]: otelcol.receiver.netflow.md
[`discovery.snmp`]: ../discovery/discovery.snmp.md
