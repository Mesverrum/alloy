# Network SNMP library (this fork)

Grafana Alloy network-collector fork: a **curated snmp_exporter module library** plus Prometheus-shaped **SNMP service discovery**. Traps and flow are later slices.

This is a fork of [grafana/alloy](https://github.com/grafana/alloy) (Apache-2.0). Device-family OID lists come from [kentik/snmp-profiles](https://github.com/kentik/snmp-profiles) (Apache-2.0). Attribution: [`snmp/NOTICE`](../snmp/NOTICE). License text for that derived tree: [`snmp/LICENSE`](../snmp/LICENSE) (Apache-2.0). This is not a Kentik trademark license and is not a ktranslate `kentik_snmp_*` name-parity contract.

## Why this shape

Stock `prometheus.exporter.snmp` already polls. This library is **curated**, not a drop-in for bare-MIB snmp_exporter dashboards. Discovery stays Prometheus-shaped so credentials never land on labels.

| Gap | What we do | What we do **not** do |
|-----|------------|------------------------|
| Device-family OID library (CPU / mem / BGP / sensors) | Bake `snmp/snmp-network.yml` into the image with findable `snmp_*` names | Emit `kentik_snmp_*`; keep stock `ifHCInOctets` as the browse path |
| Map **credentials** + **MIB modules** onto new IPs | A **Discoverer** (`snmp-discovery`) that emits Prometheus SD | Put a CIDR walker inside the exporter; write community strings on labels; ktranslate `devices.yaml` |
| Traps / flow | Later slices | — |

The discovery contract is the one snmp_exporter already documents:

- Named `auths:` in an overlay (`auths` / `auths_file` / `SNMP_AUTHS`) or in `snmp.yml` (community / v3 secret lives there). See [`snmp/auths.example.yml`](../snmp/auths.example.yml).
- Targets carry `module=` and `auth=` (Alloy) or `__param_module` / `__param_auth` (Prometheus `file_sd`).
- `sysObjectID` → module via SuperQ **fingerprinters** ([snmp_exporter#1468](https://github.com/prometheus/snmp_exporter/issues/1468)), applied at **SD time** so the exporter stays stock until that PR lands.

**One catalog.** Fingerprinter `module=` names and `snmp.yml` `modules:` keys are the same set. snmp_exporter does not fail closed on an unknown name — it walks an empty module (`up=1`, no samples) or can panic on an index type the collector cannot render. Convert never invents sidecar names (`nokia_srlinux_hot`) unless that file exists in the converted library. Discovery intersects matcher lists with the live `config_file` and drops leftovers (logged as a warning). Ship `snmp-network.yml` and `fingerprinters.yml` from the **same convert** (same image). Do not mix a newer image library with older lab fixtures.

Fleet can only push config for modules that exist in the running binary — so the library lives **in the image** at `/etc/alloy/snmp-network.yml`.

## Build the overlay image

The discovery library is **[Mesverrum/snmp-sd](https://github.com/Mesverrum/snmp-sd)** (`go.mod` pin, currently `v0.1.1-0.20260916160351-a2aca694910b`, `main`). Do not keep a second copy under `internal/snmpdiscovery`. Bake `/etc/alloy/snmp-network.yml` from the module (`go list -m -f '{{.Dir}}'`).

Thin overlay (stock Alloy + CLI + library, no `discovery.snmp` in the binary):

```bash
docker build -f Dockerfile.network -t srl-local/alloy:network-dev .
```

Fork binary (`discovery.snmp` + otelcol syslog/traps/netflow): `ALLOY_NETWORK_FROM_SOURCE=1 make -C local alloy-network-image`.

Lab harness: `make -C local alloy-network-image` in [network-o11y-demo](https://github.com/Mesverrum/network-o11y-demo).

## Ingest profiles (rare)

`snmp/modules/` is the library. Re-run convert only when adding a vendor pack from the kentik cookbook — then edit the split YAML, not the concat file.

```bash
python3 tools/snmp-profile-convert/convert.py \
  --profiles ../snmp-profiles/profiles/kentik_snmp \
  --clean-modules
# writes:
#   snmp/auths.yml
#   snmp/modules/<vendor>/<module>.yml   # split modules (edit these)
#   snmp/snmp-network.yml                # concat for Alloy config_file
#   snmp/sysobjectid-index.yaml
#   snmp/fingerprinters.yml              # modules_hot / modules_cold / modules_topology
#   snmp/module-tiers.yaml               # full module → tier map
```

### Scrape tiers (hot / cold / topology)

Profiles are partitioned so Alloy can stagger walks:

| Tier | Interval (lab) | Contents |
|------|----------------|----------|
| **hot** | ~60s | `if_mib` / `if32_mib` **octets / oper / ifHighSpeed** + `if_interface_name` lookup; `device_base` or inlined `snmp_device_info` + `snmp_Uptime`; Nokia CPU/mem/chassis |
| **cold** | ~30m | `if_mib_meta` / `if32_mib_meta` (names/descr/`if_MAC` + **packet counters** + **errors** + **discards**), `ip_addr` (IPv4/IPv6 → ifIndex), vendor tables (identity is already on the fingerprint module, not a sibling `system_mib`) |
| **topology** | ~15m (optional) | `lldp_mib`, `bgp4_mib`, `ospf_mib` (+ name match `lldp\|cdp\|bgp\|ospf\|isis`) |

Fingerprinters emit `modules_hot` / `modules_cold` / `modules_topology`. Discovery writes three Alloy target files. Each tier is optional: `discovery.snmp` `tiers = ["hot"]` (minimum useful), `["hot","cold"]` (default), or `["hot","cold","topology"]`. Lab: `LAB_ALLOY_SNMP_TIERS=hot` / `hot,cold` / `hot,cold,topology`. `LAB_ALLOY_SNMP_TOPOLOGY=1` still adds topology when `LAB_ALLOY_SNMP_TIERS` is unset. CLI: `snmp-discovery --tiers=hot`. Disabled tiers are published as `[]` so leftover scrapes go idle.

Do **not** remote_write the raw topology tier. Scrape it into `prometheus.network_topology`, which turns LLDP, CDP, and BGP samples into `network_topology_device_info` and `network_topology_edge_info` and forwards only that graph. The same block accepts gnmic `*lldp_interface_neighbor*` series (`source`, `interface_name`, `neighbor_id`, `value`). Example: [`example/topology-glue.alloy`](../example/topology-glue.alloy).

A sample is kept only when its metric name contains one of `lldp_interface_neighbor`, `lldpremsysname`, `lldpremportid`, `lldplocport`, `cdpcachedeviceid`, `cdpcachedeviceport`, `tbgppeerngconnstate`, or `bgppeerstate`. Every other series, including histograms, is discarded in this block and is not written to `forward_to`. A commit made only of discarded series increments `ignored_commits_total` and leaves the last graph in place.

`prometheus.scrape` still copies each sample to every receiver in its `forward_to` list. Point the topology scrape at this block. Point hot, cold, node-exporter, and the rest of gnmic at the normal receiver. When this block is the only `forward_to` on a scrape, series outside that name list never leave the scrape. A metric whose name merely contains one of those substrings is treated as a neighbor sample and is also not forwarded raw.

#### Debugging `prometheus.network_topology`

These series are on Alloy's own `/metrics` endpoint, with `component_path` and `component_id`. They are not part of the graph forwarded to Grafana.

| Metric | What it means |
|--------|----------------|
| `alloy_prometheus_network_topology_samples` | Neighbor samples held, including local-port helpers. They age out after `stale_after` (default 30m). |
| `alloy_prometheus_network_topology_edges` | Edges from the last commit that contained neighbor samples. A later commit with none does not zero this. |
| `alloy_prometheus_network_topology_edges_by_evidence` | Those edges labeled `evidence` (`lldp_rem`, `gnmi_lldp`, `cdp_cache`, `nokia_bgp_peer`). A missing series means zero for that evidence. |
| `alloy_prometheus_network_topology_unmatched_samples` | Samples in the last reconcile that were not local-port helpers and matched no family. |
| `alloy_prometheus_network_topology_last_reconcile_timestamp_seconds` | Unix time of the last commit that contained neighbor samples. |
| `alloy_prometheus_network_topology_last_graph_timestamp_seconds` | Unix time of the last reconcile that produced at least one edge. |
| `alloy_prometheus_network_topology_ignored_commits_total` | Commits with no neighbor samples. The previous graph is kept. |
| `alloy_prometheus_network_topology_stale_samples_total` | Samples dropped because they were older than `stale_after`. |

Each commit also logs on the component logger:

| Level | Message | When |
|-------|---------|------|
| info | `reconciled network topology` | Neighbor samples reconciled into a graph. |
| warn | `network topology samples produced no edges` | Samples arrived and matched, and the reconcile emitted nothing. |
| warn | `network topology samples matched no family` | A sample was not a local-port helper and matched no family, while other samples still produced edges. |
| debug | `network topology kept last graph` | The commit had no neighbor samples. |
| error | `network topology forward failed` | The graph was built and `forward_to` rejected it. |

Fields on the info/warn/debug lines: `received`, `matched`, `helpers`, `unmatched`, `no_reporter`, `noisy`, `no_neighbor`, `not_established`, `self`, `stale_dropped`, `edges`, `samples_held`.

How to read a quiet graph:

- `ignored_commits_total` climbs and `last_reconcile` stays put: the topology scrape, or the gnmic neighbor series, is not forwarded into this block.
- `last_reconcile` is fresh, `unmatched_samples` is above zero, `last_graph` is old: the metric names are not in the family catalog.
- `last_reconcile` is fresh, `matched` in the warn line is above zero, `edges` is 0: the join dropped the rows. `no_neighbor` is a missing remote name, `noisy` is a phone or AP name, `not_established` is a BGP session that is not up, `self` is a device reporting itself.
- `samples` is 0 and `edges` is still above zero: the held samples aged out. `stale_samples_total` increased. The last graph is still what was forwarded.
- `network topology forward failed`: the graph was built and did not leave the component.

Converter maps kentik profile YAML (numeric OIDs) → snmp_exporter **runtime** format. It does **not** run the MIB generator (no vendor MIB sources required).

**Split modules:** snmp_exporter accepts multiple `--config.file` / globs; Alloy’s `prometheus.exporter.snmp` still has a **single** `config_file`. We keep one module per file under `snmp/modules/` and concatenate into `snmp-network.yml` for the running image. Prefer editing split files and re-running the converter.

**Profile conversion rules** (keep these when adding vendors):

1. **Entry `.1`** — kentik table symbols are already `table.1.column`. Keep that full column OID as the snmp_exporter metric `oid`; do not strip the Entry.
2. **Full MIB INDEX** — declare every INDEX component in `TABLE_INDEXES`. Incomplete indexes collapse rows onto the same labels and fail the scrape (`collected before with the same name and label values`). ktranslate often tolerates loose indexing; snmp_exporter does not.
3. **Verify against a live walk** — OID suffix after the column must match the declared index arity (e.g. fans `…1.2.3.1.N` → 3 parts; some PM rows are a single packed sub-id).
4. Pair vendor modules with embedded `if_mib` via `config_merge_strategy = "merge"`.

`extends: [system-mib.yml, if-mib.yml]` drives the discovery **module chain** (kentik `system-mib.yml` is skipped — identity is inlined). The converter **partitions** that chain into hot / cold / topology (see scrape tiers above). Pair vendor modules with this library’s `if_mib` via `config_merge_strategy = "replace"` — do **not** merge stock embedded `snmp.yml`.

```alloy
// hot targets → module=if_mib,nokia_srlinux   (snmp_device_info lives on the vendor module)
// cold targets → module=if_mib_meta
local.file "snmp_targets_hot" {
  filename       = "/etc/alloy/snmp-targets.yml"
  detector       = "poll"
  poll_frequency = "15s"
}

prometheus.exporter.snmp "fabric_hot" {
  targets = encoding.from_yaml(local.file.snmp_targets_hot.content)
}
```

Discovery emits tiered module lists. Legacy `modules:` on fingerprinters remains the full chain for older tools. `_general` bases are converted modules in this library.

### Metric names (curated `snmp_*`)

Every converted series is `snmp_<stem>` so it clusters in Explore next to `node_*` / `windows_*`. Type `snmp_` or `{__name__=~"snmp_.*", job="alloy-snmp"}`.

| Profile | Stem | Emitted |
|---------|------|---------|
| Vital `tag` (`CPU`, `MemoryUsed`, `MemoryFree`, `MemoryTotal`, `Temperature`) | the tag | `snmp_CPU` |
| Everything else | MIB object | `snmp_ifHCInOctets`, `snmp_tBgpPeerNgConnState` |

Lookup labels (`ifName`, `hw_name`, `peer_as`) are not prefixed. Native MIB object stays in metric `help`. Composite % used (memory, error rate) belong in a recording rule or panel — not in this converter.

OTEL identity (not a rename): `snmp_CPU` ≈ `hw.cpu.utilization` (usually 0–100); memory stems ≈ hardware memory with **vendor-native units** (Nokia is KB).

This library is curated `snmp_*` names, not stock snmp_exporter bare-MIB series and not `kentik_snmp_*`.

Interface counters are Prometheus **counters**: `rate(snmp_ifHCInOctets[$__rate_interval]) * 8`. Do not copy ktranslate’s delta-gauge `* 8 / 60`.

## if_mib / device_base (our library, not stock)

Converted from kentik `_general/` plus a generated **`device_base`** (SNMPv2 identity for unknown sysObjectID) and an authored **`ip_addr`** (IP-MIB address tables). **Hot** scrape uses `if_mib` (octets / oper / ifHighSpeed) and the fingerprint module’s inlined `snmp_device_info`. **Cold** uses `if_mib_meta` (names, `if_MAC` as snmp_exporter `PhysAddress48` — MIB `PhysAddress` panics the collector, packet counters, errors, discards) + `ip_addr` (+ vendor tables that are not on hot). There is no sibling `system_mib` scrape — two `snmp_device_info` families in one `module=` list collide. Alloy must load `snmp-network.yml` with **`config_merge_strategy = "replace"`** so stock embedded modules are not mixed in.

**Dashboard join (IP → interface):** snmp_exporter lookups cannot stamp addresses onto `ifHCInOctets` (address-table INDEX is the IP, not ifIndex). Cold gauges carry `ifIndex` as a **label**:

```promql
# Inventory table — already has if_interface_name via chained ifName lookup
snmp_ipAdEntIfIndex{job="alloy-snmp"}

# Optional: attach IPs onto IF-MIB rows (1:many — fans out counters; prefer a table panel)
count by (device_name, ifIndex, ipAdEntAddr) (snmp_ipAdEntIfIndex)
```

Do not multiply octet counters by the raw `snmp_ipAdEntIfIndex` value (that value *is* ifIndex).

## Enum policy for converted vendor modules

Mirror stock `if_mib` + kentik’s metric vs tag split:

- **symbols** (own metrics, &lt;~30m change matters): inventory enums → `EnumAsInfo`; status enums → `gauge` with `enum_values` retained (not StateSet); **OBJECT-TYPE SYNTAX** from `snmp/oid-syntax.yaml` (public OID lookup, not a shipped MIB tree) decides counter vs gauge — Counter32/64 must not be `gauge` or the PDU is dropped. Name hints are fallback only.
- **metric_tags** (stable enrichment): snmp_exporter `lookups`; enum on a tag → lookup `EnumAsInfo` (string on the label).

**Admin-down interfaces:** `if_mib` / `if32_mib` include snmp_exporter `filters` (list form, `ifAdminStatus=1`) and column-level `walk`s (metric **and** lookup OIDs, so ifName is actually collected) so admin-down ifIndexes are never collected. Hot `if_mib` also exports `snmp_ifHighSpeed` (Gauge32 Mbps) for utilization. Do not attempt value-based drops in Alloy `prometheus.relabel`.

## Discovery

Binary: `/usr/bin/snmp-discovery`. The admin object is a **group file** (CIDR + named auths), not `--cidrs` with a global try-list. Docs: [`tools/snmp-discovery/README.md`](../tools/snmp-discovery/README.md).

The laptop scrape path stays `local.file` + `encoding.from_yaml`. HTTP SD is the poller-pool catalog (one writer; N scrapers hashmod `__address__` **before** `prometheus.exporter.snmp`).

Finding devices: **sweep** (ICMP then SNMP on new CIDR candidates; always re-probe catalog/seeds) and **crawl** (LLDP/CDP, one hop per interval, IPv4/IPv6 neighbors). Named `auths` support SNMPv1/v2c and **v3 USM** (`security_level` / `auth_protocol` / `priv_protocol` as in snmp_exporter — secrets stay in `snmp.yml`). Sweep CIDRs max ~1024 without `allow_large` (IPv4 `/22`, IPv6 `/118`). Housekeeping: `--misses` consecutive silent cycles (default 3). Catalog publish is atomic (temp+rename). Prefer `--interval 24h`+ in production. Still later: ARP/OSPF crawl.

```bash
snmp-discovery \
  --config /etc/alloy/snmp-discovery.yml \
  --overrides /etc/alloy/snmp-overrides.yml \
  --snmp-config /etc/alloy/snmp-network.yml \
  --fingerprinters /etc/alloy/fingerprinters.yml \
  --out-alloy /etc/alloy/snmp-targets.yml \
  --out-file-sd /etc/alloy/snmp-file-sd.json \
  --interval 24h \
  --misses 3 \
  --listen :9780
```

| URL | For |
|-----|-----|
| `GET /sd` | Alloy `discovery.http` (`name` / `module` / `auth` / `address`) |
| `GET /sd/prometheus` | Classic Prometheus (`__param_module` / `__param_auth`) |
| `GET /sd?shard=0&shards=4` | Pre-filtered catalog (same MD5 hashmod as Alloy relabel) |
| `GET /healthz` | Liveness |

Each group tries only its own named auths on its CIDRs. Overrides pin/ignore/rename by IP. `--interval` reloads the group file each pass; production cadence is hours–days. `--misses` is consecutive silent cycles before drop (ktranslate model). `--listen` keeps the process up even when `--interval` is 0. Profile conversion is a solved side quest — this Discoverer is the product gap vs ktranslate.

## Roadmap

| Slice | Component | Status |
|-------|-----------|--------|
| 1 | Curated `snmp.yml` modules (converter exists; more vendors are mechanical) | this branch |
| 2 | `discovery.snmp` (experimental) + `snmp-discovery` CLI / HTTP SD | **this branch** — slog, health, metrics, Live Debugging, unmarshal tests. Remaining GA items: [`docs/discovery-snmp-production-gaps.md`](discovery-snmp-production-gaps.md) |
| 3 | `otelcol.receiver.snmptrap` — [alloy#440](https://github.com/grafana/alloy/issues/440) | **this branch** (experimental) — OTel logs (not Loki). Optional `targets` join to `device_name`. Prior art: [`docs/snmp-trap-prior-art.md`](snmp-trap-prior-art.md) |
| 4 | `otelcol.receiver.netflow` — [alloy#6304](https://github.com/grafana/alloy/issues/6304) | **this branch** (experimental) — contrib receiver as-is (logs). Metrics via `otelcol.connector.signaltometrics`, not a metrics-emitting fork. Docs: [`otelcol.receiver.netflow.md`](sources/reference/components/otelcol/otelcol.receiver.netflow.md) |

`discovery.snmp` is the Fleet-managed form of slice 2. Docs: [`docs/sources/reference/components/discovery/discovery.snmp.md`](sources/reference/components/discovery/discovery.snmp.md). The overlay `Dockerfile.network` still ships only the CLI on stock Alloy for fast MIB iteration.

Syslog on the network path is `otelcol.receiver.syslog` (contrib wrap). `protocol = "none"` keeps non-RFC bodies (PRI still decoded when present); `on_error = "send"` never drops a failed parse. Optional `targets` join stamps `device_name` the same way as traps and netflow. `loki.source.syslog` remains for Cisco `rfc3164_cisco_components` if those extra fields must be *parsed*, not just ingested.
