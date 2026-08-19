# snmp-discovery

Prometheus-shaped SNMP **service discovery** (not an exporter).

The admin object is a **group file**: CIDR + named `auths` (ktranslate `groups/*.env` equivalent). It writes Prometheus SD; stock `prometheus.exporter.snmp` stays a scraper. Do not put a CIDR walker inside the exporter. Do not write a ktranslate `devices.yaml`.

Discovery is **one writer**. A pool of pollers consumes the catalog (files or HTTP). Shard **before** the SNMP walk — duplicate remainder is double walks.

## What you configure

| Field | Meaning |
|-------|---------|
| `groups[].cidrs` | Allow-list (crawl) and sweep range. Max **~1024 hosts** without `allow_large` (IPv4 **/22**, IPv6 **/118**) |
| `groups[].exclude` | LibreNMS-style `nets-exclude` |
| `groups[].seeds` | Crawl starting IPs (and always SNMP-probed) |
| `groups[].mode` | `sweep`, `crawl`, or `both` (default) |
| `groups[].ping` | ICMP-filter **sweeps** only (default true). Crawl neighbors are not ping-gated |
| `groups[].auths` | Named `snmp.yml` auths to try **only on that group** (order = try order) |
| `groups[].fingerprinter` | SuperQ #1468 matchers → `module=` |
| `overrides` | ignore / rename / pin module or auth by IP |

Community / v3 secret never appears in this file or in SD labels. Catalog `address` values are canonical host IPs (IPv6 compressed, **no brackets**) — the form snmp_exporter accepts as `target` without a port. Do not emit `[2001:db8::1]` without `:161`; use bare `2001:db8::1` or `[2001:db8::1]:161`.

**Finding devices** (output is still Prometheus SD — crawl does not change the contract):

- **Sweep** — ping the CIDR, then SNMP GET sys* on responders (ktranslate / LibreNMS `snmp-scan`). `/21` and wider are refused. `ping: false` SNMPs every hole in the `/22`. **Known catalog/seed IPs are always re-probed** even if ping is down this cycle (Zabbix-style independent checks).
- **Crawl** — SNMP walk LLDP management addresses + CDP on seeds and catalog members; probe neighbors that fall inside `cidrs` (LibreNMS xDP). **One hop per interval** — a deep fabric fills in over several discovery cycles. Probe and crawl use the same named `auths` (v1/v2c community or SNMPv3 USM from `snmp.yml`). IPv4 and IPv6 neighbors are accepted when they fall in `cidrs`. No ARP/OSPF/BGP crawl yet.
- **Sticky catalog (ktranslate-style)** — a miss increments a per-target counter; drop only after `--misses` consecutive discovery cycles with no response (default **3**). `--misses 0` never purges. Counters persist in `--state`. Empty or **failed** scans do not advance misses or rewrite SD. `overrides.ignore` removes the address from the catalog immediately.
- **Publish** — YAML / file_sd / state are written via temp + rename (no half-read catalogs). Overlapping ticks are skipped while a scan is still running.

Discovery cadence is meant to be **hours to days** in production (`--interval 24h` or `168h`), not minutes. Lab compose keeps `5m` for fast iteration; purge latency is then `misses × interval` (e.g. daily × 3 = three days; weekly × 2 = two weeks).

`--ping=false` globally turns ICMP off. Discoverer needs `CAP_NET_RAW` or Linux `ping_group_range` when ping is on.

```bash
go test ./...
go build -o snmp-discovery .

snmp-discovery \
  --config snmp-discovery.example.yml \
  --snmp-config /etc/alloy/snmp-network.yml \
  --fingerprinters /etc/alloy/fingerprinters.yml \
  --out-alloy /etc/alloy/snmp-targets.yml \
  --out-file-sd /etc/alloy/snmp-file-sd.json \
  --interval 24h \
  --misses 3 \
  --listen :9780
```

`--interval 0` is one-shot (exits after the scan) unless `--listen` is set, in which case the process stays up and serves the last catalog.

One-shot flags still work (`--cidrs` + `--auths`) for a single anonymous group.

## Catalog consumers

| Path | Format | Consumer |
|------|--------|----------|
| `--out-alloy` | YAML list (`name`, `address`, `module`, `auth`) | Alloy `encoding.from_yaml` |
| `--out-file-sd` | Prometheus file_sd (`__param_module` / `__param_auth`) | Classic Prometheus + snmp_exporter |
| `GET /sd` | Prometheus http_sd JSON with Alloy labels (`name`, `module`, `auth`, `address`) | Alloy `discovery.http` → `prometheus.exporter.snmp` |
| `GET /sd/prometheus` | Same JSON with `__param_*` | Classic Prometheus `http_sd_configs` |
| `GET /alloy` | Same YAML as `--out-alloy` | Debug / `local.file` equivalent over HTTP |
| `GET /healthz` | Plain text | Liveness |

Label `snmp_group` is the group name, not a secret. Do **not** put `__param_*` on the Alloy `/sd` path — those keys are not in `prometheus.exporter.snmp` ignored labels and would leak onto series.

Optional `?shard=0&shards=4` on `/sd`, `/sd/prometheus`, and `/alloy` filters with the **same hashmod as Alloy/Prometheus relabel** (MD5 of the device address, last 8 bytes `% shards`). Prefer hashmod in each poller on the **full** `/sd` so Fleet can push identical config plus `SHARD_ID` / `SHARD_COUNT`. Query-param filter is for pollers that cannot relabel, and for `curl` checks.

### Poller pool (hashmod before the walk)

N shards, **one active poller each**. Discovery stays a single writer; pollers do not need to know N from the catalog.

```alloy
discovery.http "snmp_catalog" {
  url = "http://snmp_discovery:9780/sd"
}

discovery.relabel "snmp_shard" {
  targets = discovery.http.snmp_catalog.targets

  rule {
    source_labels = ["__address__"]
    target_label  = "__tmp_hash"
    modulus       = 4          // SHARD_COUNT — must match the pool size
    action        = "hashmod"
  }

  rule {
    source_labels = ["__tmp_hash"]
    regex         = "^0$"      // SHARD_ID of this collector
    action        = "keep"
  }
}

prometheus.exporter.snmp "fabric" {
  config_file           = "/etc/alloy/snmp-network.yml"
  config_merge_strategy = "merge"
  targets               = discovery.relabel.snmp_shard.output
}
```

Hash `__address__` (the SNMP IP). Filter **before** `prometheus.exporter.snmp` so unused shards never walk.

Fingerprint matchers are the #1468 data model, applied at SD time so the exporter binary does not change.
