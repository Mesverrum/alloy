---
canonical: https://grafana.com/docs/alloy/latest/reference/components/otelcol/otelcol.receiver.netflow/
description: Learn about otelcol.receiver.netflow
labels:
  stage: experimental
  products:
    - oss
title: otelcol.receiver.netflow
---

# `otelcol.receiver.netflow`

{{< docs/shared lookup="stability/experimental.md" source="alloy" version="<ALLOY_VERSION>" >}}

`otelcol.receiver.netflow` accepts NetFlow v5/v9, IPFIX, or sFlow datagrams over UDP and forwards each flow record as an OpenTelemetry **log**.
It does not emit metrics. To turn flow records into sums, pipe the logs into [`otelcol.connector.signaltometrics`][].

{{< admonition type="note" >}}
`otelcol.receiver.netflow` is a wrapper over the upstream OpenTelemetry Collector [`netflow`][] receiver.
Bug reports or feature requests will be redirected to the upstream repository, if necessary.

[`netflow`]: https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/{{< param "OTEL_VERSION" >}}/receiver/netflowreceiver
{{< /admonition >}}

You can specify multiple `otelcol.receiver.netflow` components by giving them different labels.
Use one component per scheme (NetFlow/IPFIX vs sFlow) because each listener binds one UDP port.

Parsed log attributes follow the upstream receiver (OpenTelemetry semantic conventions plus `flow.*`):

* `source.address`, `source.port`, `destination.address`, `destination.port`
* `network.transport`, `network.type`
* `flow.io.bytes`, `flow.io.packets`, `flow.sampler_address`, `flow.type`, `flow.sampling_rate`

When `targets` is set, a matching catalog IP (primary `address` or `snmp_aliases`) stamps `device_name` and `snmp_group` on the log record. Catalog refreshes do **not** restart the UDP listener — only listen settings (`scheme`, `hostname`, `port`, sockets/workers/queue, `send_raw`) or `output` do.

`otelcol_receiver_netflow_joined_total` / `unjoined_total` increment only while a catalog is set.

## Usage

```alloy
otelcol.receiver.netflow "<LABEL>" {
  scheme = "netflow"
  port   = 2055

  output {
    logs = [...]
  }
}
```

## Arguments

You can use the following arguments with `otelcol.receiver.netflow`:

| Name         | Type     | Description                                                                 | Default     | Required |
|--------------|----------|-----------------------------------------------------------------------------|-------------|----------|
| `scheme`     | `string` | Flow protocol. Must be `"netflow"` (NetFlow v5/v9 + IPFIX) or `"sflow"`.    | `"netflow"` | no       |
| `hostname`   | `string` | Address to bind. Empty listens on all interfaces.                           | `""`        | no       |
| `port`       | `number` | UDP port to listen on.                                                      | `2055`      | no       |
| `sockets`    | `number` | Number of UDP sockets.                                                      | `1`         | no       |
| `workers`    | `number` | Decode workers.                                                             | `2`         | no       |
| `queue_size` | `number` | Inbound packet queue depth.                                                 | `1000`      | no       |
| `send_raw`   | `bool`   | Forward the undecoded message as the log body instead of parsed attributes. | `false`     | no       |
| `targets`    | `list(map(string))` | Optional discovery catalog (typically [`discovery.snmp`](../../discovery/discovery.snmp.md) `.targets` or file-SD with `address` / `device_name` / `snmp_aliases`). Joins `flow.sampler_address` to `device_name` without restarting the UDP listener. Matching `source.address` / `destination.address` stamp `src_device` / `dst_device`. | | no |

## Blocks

You can use the following blocks with `otelcol.receiver.netflow`:

{{< docs/alloy-config >}}

| Block                            | Description                                                                | Required |
|----------------------------------|----------------------------------------------------------------------------|----------|
| [`output`][output]               | Configures where to send received telemetry data.                          | yes      |
| [`debug_metrics`][debug_metrics] | Configures the metrics that this component generates to monitor its state. | no       |

[debug_metrics]: #debug_metrics
[output]: #output

{{< /docs/alloy-config >}}

### `output`

{{< badge text="Required" >}}

{{< docs/shared lookup="reference/components/output-block-logs.md" source="alloy" version="<ALLOY_VERSION>" >}}

### `debug_metrics`

{{< docs/shared lookup="reference/components/otelcol-debug-metrics-block.md" source="alloy" version="<ALLOY_VERSION>" >}}

## Exported fields

`otelcol.receiver.netflow` doesn't export any fields.

## Component health

`otelcol.receiver.netflow` is only reported as unhealthy if given an invalid configuration.

## Debug information

`otelcol.receiver.netflow` doesn't expose any component-specific debug information.

## Debug metrics

* `otelcol_receiver_netflow_joined_total` `counter`: Flow records whose `flow.sampler_address` matched a `targets` identity. Only increments when `targets` is set.
* `otelcol_receiver_netflow_unjoined_total` `counter`: Flow records received while `targets` was set but the sampler address was unknown.

`otelcol.receiver.netflow` also exposes the usual [`debug_metrics`](#debug_metrics) for the wrapped contrib receiver.

## Example

Receive NetFlow/IPFIX on UDP 2055, optionally keep the records as logs, and generate cumulative byte/packet sums with `otelcol.connector.signaltometrics`.

The sums are **cumulative**. Use `rate()` in PromQL. Do not treat them as ktranslate 60s top-K gauges (`sum(...) * 8 / 60`).

```alloy
otelcol.receiver.netflow "ipfix" {
  scheme  = "netflow"
  port    = 2055
  targets = discovery.snmp.fabric.targets

  output {
    logs = [
      otelcol.connector.signaltometrics.netflow.input,
      otelcol.exporter.debug.logs.input,
    ]
  }
}

otelcol.connector.signaltometrics "netflow" {
  error_mode = "ignore"

  logs {
    name        = "network.io.by_flow"
    description = "Bytes observed in decoded flow records"
    unit        = "By"
    attributes {
      key = "source.address"
    }
    attributes {
      key = "source.port"
    }
    attributes {
      key = "destination.address"
    }
    attributes {
      key = "destination.port"
    }
    attributes {
      key = "network.transport"
    }
    attributes {
      key = "flow.sampler_address"
    }
    attributes {
      key = "device_name"
    }
    attributes {
      key = "src_device"
    }
    attributes {
      key = "dst_device"
    }
    sum {
      value = "Int(attributes[\"flow.io.bytes\"])"
    }
  }

  logs {
    name        = "network.io.by_flow.packets"
    description = "Packets observed in decoded flow records"
    unit        = "{packets}"
    attributes {
      key = "source.address"
    }
    attributes {
      key = "source.port"
    }
    attributes {
      key = "destination.address"
    }
    attributes {
      key = "destination.port"
    }
    attributes {
      key = "network.transport"
    }
    attributes {
      key = "flow.sampler_address"
    }
    attributes {
      key = "device_name"
    }
    attributes {
      key = "src_device"
    }
    attributes {
      key = "dst_device"
    }
    sum {
      value = "Int(attributes[\"flow.io.packets\"])"
    }
  }

  output {
    metrics = [otelcol.exporter.debug.metrics.input]
  }
}

otelcol.exporter.debug "logs" {}
otelcol.exporter.debug "metrics" {}
```

<!-- START GENERATED COMPATIBLE COMPONENTS -->

## Compatible components

`otelcol.receiver.netflow` can accept arguments from the following components:

- Components that export [OpenTelemetry `otelcol.Consumer`](../../../compatibility/#opentelemetry-otelcolconsumer-exporters)


{{< admonition type="note" >}}
Connecting some components may not be sensible or components may require further configuration to make the connection work correctly.
Refer to the linked documentation for more details.
{{< /admonition >}}

<!-- END GENERATED COMPATIBLE COMPONENTS -->

[`otelcol.connector.signaltometrics`]: otelcol.connector.signaltometrics.md
