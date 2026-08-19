# SNMP trap receiver — prior art (ktranslate + Telegraf)

**Status (2026-08-18):** experimental `loki.source.snmptrap` is in the Alloy `network-snmp` fork (`internal/snmptrap` + component). Default listen `:1620`, optional community allowlist (omit = accept all), gosmi enrichment fail-open, drop-on-full. Lab cutover of the SRL trap-group is still TODO.

**Goal for Alloy:** a logging capability (`loki.source.snmptrap`, [alloy#440](https://github.com/grafana/alloy/issues/440)) that listens for SNMP traps/informs and forwards structured log entries — peer of `loki.source.syslog`, not a metrics scrape.

This note captures how the two tools we already trust handle traps, so the Alloy design can borrow deliberately.

---

## Shared foundation

Both use **`github.com/gosnmp/gosnmp`** `TrapListener`:

- UDP listen (default privileged **162**; ktranslate lab uses **1620** in-container + host map `162:1620/udp`)
- Callback `OnNewTrap(packet *gosnmp.SnmpPacket, addr *net.UDPAddr)`
- SNMPv1 / v2c / v3 (USM) support
- Identify trap via **`SNMPv2-MIB::snmpTrapOID.0`** (`.1.3.6.1.6.3.1.1.4.1.0`); v1 mapped per RFC 2576

| Concern | Telegraf | ktranslate |
|---------|----------|------------|
| Output signal | **Metric** (`snmp_trap` measurement) | **Event / log** (`EventType=KSnmpTrap` → OTLP logs / NR Events) |
| MIB resolve | gosmi (preferred) or netsnmp `snmptranslate` | Bundled **mibs.db** + profile trap defs |
| Device identity | Source IP (+ v3 engine/context) | Device map by IP / EngineID; else reverse DNS |
| Undefined OIDs | Lookup failure → **drop whole trap** (strict) | Optional `drop_undefined`; else keep numeric OID keys |
| Community | Emitted as tag (v1/v2c) | Configured but historically still accepts non-matching |
| Volume metric | Implicit via metric points | CHF meter `snmp_traps` |

For Alloy-as-logs, **ktranslate’s event path is the closer product model**; Telegraf’s listener + tag/field shape is the cleaner **transport/API** reference. Upstream #440 comments already use Telegraf→Loki as a workaround.

---

## Telegraf `inputs.snmp_trap`

**Code:** [`plugins/inputs/snmp_trap/snmp_trap.go`](https://github.com/influxdata/telegraf/blob/master/plugins/inputs/snmp_trap/snmp_trap.go)  
**Docs:** [Telegraf snmp_trap](https://docs.influxdata.com/telegraf/v1/input-plugins/snmp_trap/)

### Shape

- **Service input** (listen forever; `Gather` is a no-op)
- Config: `service_address = "udp://:162"`, `version`, v3 secrets, MIB `path`
- Handler builds one metric:

```text
measurement: snmp_trap
tags:    source, version, oid, name, mib [, community | context_name, engine_id] [, agent_address]
fields:  each varbind after MIB lookup (name → value); v1 adds sysUpTimeInstance
```

Example:

```text
snmp_trap,mib=SNMPv2-MIB,name=coldStart,oid=.1.3.6.1.6.3.1.1.5.1,source=192.168.122.102,version=2c,community=public sysUpTimeInstance=1i …
```

### Behaviour worth copying

1. **Trap identity tags** — `oid` / `name` / `mib` from snmpTrapOID (easy LogQL filters)
2. **v1→v2 OID mapping** (generic + enterprise-specific)
3. **OctetString** — UTF-8 vs hex
4. **ObjectIdentifier values** resolved to textual names when possible
5. **Privileged port** guidance (`setcap CAP_NET_BIND_SERVICE`, or listen high + NAT)
6. **gosmi** translator path (no shelling out to `snmptranslate` in production)

### Behaviour to avoid for Alloy logs

- Emitting as **metrics** (cardinality + wrong semantics for link flaps / coldStart)
- **Fail-closed on any unresolved OID** (drops useful traps when MIBs incomplete)
- Putting **community** on every series/log by default (secret-adjacent; prefer optional / hashed / omit)

---

## ktranslate SNMP traps

**Code:** [`pkg/inputs/snmp/traps/traps.go`](https://github.com/kentik/ktranslate/blob/master/pkg/inputs/snmp/traps/traps.go)  
**Config:** `snmp-base.yaml` → `trap:` ([wiki](https://github.com/kentik/ktranslate/wiki/Advanced-Ktranslate-Configuration))  
**OTLP path:** [`pkg/formats/otel/otel.go`](https://github.com/kentik/ktranslate/blob/master/pkg/formats/otel/otel.go) — traps are **not** metrics; they flatten to JSON and go on the **log tee**

### Config (lab-relevant)

```yaml
trap:
  listen: 0.0.0.0:1620
  community: public
  version: ""          # default v2c
  transport: ""        # default udp
  v3_config: null
  trap_only: false     # true → no poll/ICMP in this process
  drop_undefined: false
```

Docker: `-p 162:1620/udp`. In this lab, traps go to the **SNMP poller** container (`ktranslate_snmp_*:1620`), not a separate trap-only process.

### Handle pipeline

1. Mark CHF `snmp_traps` meter
2. Resolve **device** from `deviceMap[srcIP]` or v3 **EngineID**; else IP + optional reverse DNS → `ProviderTrapUnknown`
3. Build **JCHF** with `EventType = "KSnmpTrap"` (`kt.KENTIK_EVENT_SNMP_TRAP`)
4. Find trap OID varbind → `TrapOID`, optional `TrapName` / `Index` from mibdb
5. v1: `GenericTrap`, `SpecificTrap`, `Enterprise`, `Timestamp`
6. Other varbinds → `CustomStr` / `CustomBigInt` (MIB name if known, else numeric OID); honor conversions / `drop_undefined`
7. Push to `jchfChan`

### OTLP / Loki shape (what dashboards query today)

```go
case kt.KENTIK_EVENT_SNMP_TRAP, kt.KENTIK_EVENT_EXT:
    flat := in.Flatten()
    b, _ := json.Marshal(flat)
    f.logTee <- string(b)   // OTLP logs, not metrics
```

Lab LogQL (see `local/docs/dashboard-query-lessons.md`):

```logql
{service_name=~"ktranslate.*"} | json | eventType="KSnmpTrap"
```

Do **not** use `rate(kentik_ktranslate_chf_kkc_snmp_traps[5m])` for event volume panels — CHF is collector health, not trap content.

### Behaviour worth copying

1. **Traps as logs/events**, not gauges
2. **Device enrichment** from known inventory (IP / EngineID) without requiring SNMP GET
3. **`drop_undefined` policy** (fail-open default; optional strict)
4. **Sticky identity fields**: `TrapOID`, `TrapName`, `device_name` / `SrcAddr`
5. **trap_only** mode for dedicated receivers
6. **Non-blocking log tee** with drop-on-full (backpressure story)

### Behaviour to rethink for Alloy

- Community “accept anyway” — Alloy should document explicit community/v3 allowlists
- Heavy **mibs.db** / profile coupling — Alloy may start with gosmi + optional MIB dirs (Telegraf-like), add profile enrichment later
- Flatten-everything JSON — prefer **stable labels** + JSON body (syslog-style) for LogQL

---

## Alloy design implications (`loki.source.snmptrap`)

Mirror **`loki.source.syslog`**: listen → build `loki.Entry` → `forward_to`.

### Suggested contract

| Piece | Proposal |
|-------|----------|
| Component | `loki.source.snmptrap` (experimental), [alloy#440](https://github.com/grafana/alloy/issues/440) |
| Listen | `listen_address` / UDP (default `:1620` in containers; doc `:162` + caps) |
| Versions | `1`, `2c`, `3` blocks (secrets via `alloytypes.Secret`) |
| Labels | `__snmptrap_source`, `__snmptrap_oid`, `__snmptrap_name`, `__snmptrap_mib`, `__snmptrap_version`; `device_name` / `snmp_group` when `targets` is set |
| Body | JSON of varbinds (string/number) — ktranslate-like content, Telegraf-like names |
| Community | Do **not** put on labels by default; optional `include_community` |
| MIB | **gosmi** on a curated path first (optional enrichment). Fail-open to numeric OIDs if lookup misses. Later: manual dictionary enrichment and/or pivot to a curated library (ktranslate-style) — not a v1 blocker. |
| Metrics | received / decode_error / dropped_undefined / listen_error (syslog peer) |
| Privileges | Document `CAP_NET_BIND_SERVICE` or high port + DNAT |

**MIB stance (decided 2026-08-18):** start with gosmi + a small known-good MIB set in the network image (or mount). Do not dump distro/Cisco mega-trees into gosmi. Name enrichment is best-effort; trap receive must work without it.

### Decided (2026-08-18)

| # | Decision | Choice |
|---|----------|--------|
| — | **MIB enrichment** | gosmi + small curated set; fail-open to numeric OIDs; curated dictionary later |
| 1 | **Default listen port** | `:1620` in docs/examples; override allowed. Lab maps host 162→1620. |
| 2 | **Auth / community** | **Optional.** Omit or empty `communities` ⇒ accept all (common customer practice — most do not filter on trap community). If set, allowlist only. Document clearly so operators who need filtering can opt in. |
| 3 | **Community on labels** | Never by default (`include_community` opt-in only — secret-adjacent). |
| 4 | **Log body shape** | Structured JSON + stable `__snmptrap_*` labels. |
| 5 | **Undefined OID policy** | Fail-open default; optional `drop_undefined` later. |
| 6 | **Informs** | Traps + informs. |
| 7 | **Device enrichment** | Source IP (+ EngineID label when present). Optional `targets` from `discovery.snmp` stamps `device_name` at receive time (aliases from hostname collapse). Syslog/flow still open. |
| 8 | **Relabel surface** | `__snmptrap_*` meta labels; promote via `discovery.relabel` / `loki.relabel`. |
| 9 | **Backpressure** | Drop on full + counter; do not stall UDP. |
| 10 | **Coexistence with ktranslate** | Lab cutover of SRL trap-group to Alloy when listener is up. |
| 11 | **Component** | `loki.source.snmptrap`, experimental until syslog-parity polish. |
| 12 | **v3 engine/context** | Always label when present. |

**Community note:** filtering is a minority need. Default ingest-all matches ktranslate’s practical behaviour and field experience; do not make empty-allowlist mean “accept nothing.”

### What not to do

- Do not invent a separate metrics pipeline for trap volume as the primary UX (CHF-style counters for **health** only)
- Do not require full snmp_exporter module profiles to receive traps (profiles help **naming**, not listening)
- Do not block Fleet: remotecfg can own the listener River once the binary has the component

### Lab bridge (today → later)

| Today (ktranslate) | Later (Alloy) |
|--------------------|---------------|
| `snmp-trap-config.sh` → poller `:1620` | Point SRL trap-group at Alloy `:1620` |
| Loki `eventType="KSnmpTrap"` | Loki labels from `loki.source.snmptrap` |
| CHF `snmp_traps` meter | Alloy component counters |

---

## References

- Telegraf: [snmp_trap.go](https://github.com/influxdata/telegraf/blob/master/plugins/inputs/snmp_trap/snmp_trap.go), [README](https://github.com/influxdata/telegraf/blob/master/plugins/inputs/snmp_trap/README.md)
- ktranslate: [traps.go](https://github.com/kentik/ktranslate/blob/master/pkg/inputs/snmp/traps/traps.go), [otel.go trap case](https://github.com/kentik/ktranslate/blob/master/pkg/formats/otel/otel.go), [wiki trap section](https://github.com/kentik/ktranslate/wiki/Advanced-Ktranslate-Configuration)
- Alloy: [issue #440](https://github.com/grafana/alloy/issues/440), peer [`loki.source.syslog`](https://grafana.com/docs/alloy/latest/reference/components/loki/loki.source.syslog/)
- Lab: `AGENTS.md` syslog/traps gotcha; `local/docs/dashboard-query-lessons.md` trap LogQL
