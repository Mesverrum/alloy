# snmp-discovery

Prometheus-shaped SNMP **service discovery** (not an exporter).

This is the Discoverer half of the usual Prometheus split: it writes targets; stock `prometheus.exporter.snmp` / snmp_exporter stay dumb scrapers. That is the shape SuperQ and snmp_exporter maintainers already expect — do not put a CIDR walker inside the exporter.

## Contract (same as Prometheus + snmp_exporter)

1. Scan CIDRs (or `/32`s).
2. Try **named** `auths` from `snmp.yml` in order. The community / v3 secret stays in `auths:`; it is **never** a target label.
3. GET `sysObjectID` / `sysName` / `sysDescr`.
4. Stamp `module=` from SuperQ-style **fingerprinters** ([snmp_exporter#1468](https://github.com/prometheus/snmp_exporter/issues/1468)). First matcher wins; unknown devices fall back to `if_mib`.
5. Dual-emit so either consumer works:

| File | Consumer |
|------|----------|
| Alloy targets YAML | Official `encoding.from_yaml(local.file….content)` shape: `name`, `address`, `module`, `auth` (+ extra keys become labels) |
| Prometheus `file_sd` JSON | `targets: [<ip>]` + `__param_module` / `__param_auth` (scrape `/snmp` with the usual `__address__` → snmp_exporter relabel) |

```bash
go test ./...
go build -o snmp-discovery .

./snmp-discovery \
  --cidrs 172.20.20.2/32,172.20.20.3/32 \
  --auths public_v2 \
  --snmp-config /etc/alloy/snmp-network.yml \
  --fingerprinters /etc/alloy/fingerprinters.yml \
  --out-alloy /etc/alloy/snmp-targets.yml \
  --out-file-sd /etc/alloy/snmp-file-sd.json
```

Classic Prometheus scrape (for reviewers who do not run Alloy):

```yaml
scrape_configs:
  - job_name: snmp
    file_sd_configs:
      - files: ['snmp-file-sd.json']
    metrics_path: /snmp
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: 127.0.0.1:9116
```

`--auths` is the credential map: add more named blocks in `snmp.yml` (`site_v2`, `dc1_v3`, …) and list them in try-order. First GET that returns `sys*` wins; the **name** is what lands on the target.

Fingerprint matchers are the same data model SuperQ proposed for exporter-side `?fingerprint=`. Applying them at SD time is the portable subset until that lands upstream — the exporter binary does not change.
