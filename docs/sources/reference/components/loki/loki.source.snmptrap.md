---
canonical: https://grafana.com/docs/alloy/latest/reference/components/loki/loki.source.snmptrap/
aliases:
  - ../loki.source.snmptrap/ # /docs/alloy/latest/reference/components/loki/loki.source.snmptrap/
description: loki.source.snmptrap moved to otelcol.receiver.snmptrap
labels:
  stage: experimental
  products:
    - oss
title: loki.source.snmptrap
---

# `loki.source.snmptrap`

`loki.source.snmptrap` was replaced by [`otelcol.receiver.snmptrap`](../otelcol/otelcol.receiver.snmptrap.md).

Traps are OpenTelemetry **logs**, not Loki entries. Point `output.logs` at an
`otelcol.*` consumer. There is no `forward_to` / `loki.relabel` hop.
