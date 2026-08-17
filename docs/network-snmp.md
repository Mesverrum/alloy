# Network SNMP library (this fork)

Grafana Alloy network-collector fork: a **curated snmp_exporter module library** plus Prometheus-shaped **SNMP service discovery**. Traps and flow are later slices.

This is a fork of [grafana/alloy](https://github.com/grafana/alloy) (Apache-2.0). Device-family OID lists come from [kentik/snmp-profiles](https://github.com/kentik/snmp-profiles) (Apache-2.0); attribution in [`snmp/NOTICE`](snmp/NOTICE).

## Why this shape (Prometheus maintainers)

Stock `prometheus.exporter.snmp` already polls. Gaps vs a network collector:

| Gap | What we do | What we do **not** do |
|-----|------------|------------------------|
| Device-family OID library (CPU / mem / BGP / sensors) | Bake `snmp/snmp-network.yml` into the image | Invent a second metric namespace |
| Map **credentials** + **MIB modules** onto new IPs | A **Discoverer** (`snmp-discovery`) that emits Prometheus SD | Put a CIDR walker inside the exporter; write community strings on labels; ktranslate `devices.yaml` |
| Traps / flow | Later slices | — |

The discovery contract is the one snmp_exporter already documents:

- Named `auths:` in `snmp.yml` (community / v3 secret lives there).
- Targets carry `module=` and `auth=` (Alloy) or `__param_module` / `__param_auth` (Prometheus `file_sd`).
- `sysObjectID` → module via SuperQ **fingerprinters** ([snmp_exporter#1468](https://github.com/prometheus/snmp_exporter/issues/1468)), applied at **SD time** so the exporter stays stock until that PR lands.

Fleet can only push config for modules that exist in the running binary — so the library lives **in the image** at `/etc/alloy/snmp-network.yml`.

## Build the overlay image

Does **not** compile Alloy. Overlays YAML + a small `snmp-discovery` binary onto `grafana/alloy:latest`:

```bash
python3 tools/snmp-profile-convert/convert.py
docker build -f Dockerfile.network -t srl-local/alloy:network-dev .
```

Lab harness: `make -C local alloy-network-image` in [network-o11y-demo](https://github.com/Mesverrum/network-o11y-demo).

## Regenerate snmp.yml + fingerprinters

```bash
python3 tools/snmp-profile-convert/convert.py
# writes:
#   snmp/snmp-network.yml
#   snmp/sysobjectid-index.yaml
#   snmp/fingerprinters.yml
#   snmp/ktranslate-name-map.md
```

Converter maps kentik profile YAML (numeric OIDs) → snmp_exporter **runtime** format. It does **not** run the MIB generator (no vendor MIB sources required).

`extends: [system-mib.yml, if-mib.yml]` is ignored. Pair vendor modules with the **embedded** `if_mib`:

```alloy
local.file "snmp_targets" {
  filename       = "/etc/alloy/snmp-targets.yml"
  detector       = "poll"
  poll_frequency = "15s"
}

prometheus.exporter.snmp "fabric" {
  config_file           = "/etc/alloy/snmp-network.yml"
  config_merge_strategy = "merge"
  targets               = encoding.from_yaml(local.file.snmp_targets.content)
}
```

That `targets = encoding.from_yaml(...)` form is the **documented** Alloy pattern (see `prometheus.exporter.snmp` docs). Discovery writes the YAML; Alloy does not walk CIDRs.

Metric names are **native** (`sgiCpuUsage`, `ifHCInOctets`, …). See [`snmp/ktranslate-name-map.md`](snmp/ktranslate-name-map.md) for the ktranslate `tag` mapping (documentation only — no remap pipeline).

Interface counters are Prometheus **counters**: `rate(ifHCInOctets[$__rate_interval]) * 8`. Do not copy ktranslate’s delta-gauge `* 8 / 60`.

## Discovery

Binary in the overlay image: `/usr/bin/snmp-discovery`. Docs: [`tools/snmp-discovery/README.md`](../tools/snmp-discovery/README.md).

```bash
snmp-discovery \
  --cidrs 172.20.20.2/32,172.20.20.3/32 \
  --auths public_v2 \
  --snmp-config /etc/alloy/snmp-network.yml \
  --fingerprinters /etc/alloy/fingerprinters.yml \
  --out-alloy /etc/alloy/snmp-targets.yml \
  --out-file-sd /etc/alloy/snmp-file-sd.json
```

Add more named auths in `snmp-network.yml` and pass them on `--auths` in try-order. First successful `sys*` GET wins; only the **auth name** is written to SD.

## Roadmap

| Slice | Component | Status |
|-------|-----------|--------|
| 1 | Curated `snmp.yml` modules + `sysobjectid-index.yaml` | this branch |
| 2 | Prometheus-shaped `snmp-discovery` (overlay binary; dual-emit Alloy YAML + `file_sd`) | this branch |
| 3 | `loki.source.snmptrap` — [alloy#440](https://github.com/grafana/alloy/issues/440) | later |
| 4 | `otelcol.receiver.netflow` — [alloy#6304](https://github.com/grafana/alloy/issues/6304) | later |

A first-class Alloy `discovery.snmp` component is the upstreamable form of slice 2. The overlay binary is the proof that the **SD contract** is enough — no exporter changes.

Syslog is already in upstream Alloy (`loki.source.syslog`, including Cisco `rfc3164_cisco_components`).
