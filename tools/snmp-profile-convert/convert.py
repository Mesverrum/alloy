#!/usr/bin/env python3
"""Convert kentik snmp-profiles YAML into snmp_exporter runtime snmp.yml.

Does not run the MIB generator — profiles already carry numeric OIDs.
`extends` (system-mib / if-mib) is ignored: pair the vendor module with the
embedded `if_mib` via prometheus.exporter.snmp `config_merge_strategy = "merge"`.

Apache-2.0 profiles: see snmp/NOTICE (kentik/snmp-profiles).
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError as exc:  # pragma: no cover
    raise SystemExit("PyYAML required: pip install pyyaml") from exc

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PROFILES = ROOT / "snmp" / "profiles"
DEFAULT_SNMP_OUT = ROOT / "snmp" / "snmp-network.yml"
DEFAULT_INDEX_OUT = ROOT / "snmp" / "sysobjectid-index.yaml"
DEFAULT_FP_OUT = ROOT / "snmp" / "fingerprinters.yml"

# Known table INDEX clauses (numeric OIDs → snmp_exporter index defs).
# Fallback for unknown tables is a single gauge index named `index`.
TABLE_INDEXES: dict[str, list[dict[str, str]]] = {
    # TIMETRA-CHASSIS-MIB
    "1.3.6.1.4.1.6527.3.1.2.2.1.8": [
        {"labelname": "tmnxChassisIndex", "type": "gauge"},
        {"labelname": "tmnxHwIndex", "type": "gauge"},
    ],
    "1.3.6.1.4.1.6527.3.1.2.2.1.24.1": [
        {"labelname": "tmnxPhysChasFanChassisIndex", "type": "gauge"},
        {"labelname": "tmnxPhysChasFanIndex", "type": "gauge"},
    ],
    "1.3.6.1.4.1.6527.3.1.2.2.1.24.9": [
        {"labelname": "tmnxPhysChasPMChassisIndex", "type": "gauge"},
        {"labelname": "tmnxPhysChasPMIndex", "type": "gauge"},
    ],
    # TIMETRA-BGP-MIB
    "1.3.6.1.4.1.6527.3.1.2.14.4.7": [
        {"labelname": "vRtrID", "type": "gauge"},
        {"labelname": "tBgpPeerNgAddressType", "type": "InetAddressType"},
        {"labelname": "tBgpPeerNgAddress", "type": "InetAddress"},
    ],
    "1.3.6.1.4.1.6527.3.1.2.14.4.8": [
        {"labelname": "vRtrID", "type": "gauge"},
        {"labelname": "tBgpPeerNgAddressType", "type": "InetAddressType"},
        {"labelname": "tBgpPeerNgAddress", "type": "InetAddress"},
    ],
    # LENOVO-ENV-MIB
    "1.3.6.1.4.1.19046.2.3.11.1.1": [
        {"labelname": "lenovoEnvMibPowerSupplyIndex", "type": "gauge"},
    ],
    "1.3.6.1.4.1.19046.2.3.11.1.2": [
        {"labelname": "lenovoEnvMibFanIndex", "type": "gauge"},
    ],
    "1.3.6.1.4.1.19046.2.3.11.1.3": [
        {"labelname": "lenovoEnvMibTempSensorIndex", "type": "gauge"},
    ],
}

GAUGE_TAG_HINT = re.compile(
    r"(as|index|prefixes|flaps|rpm|percent|temperature|threshold|total|used|free|available)$",
    re.I,
)


def module_name_from_path(path: Path) -> str:
    return path.stem.replace("-", "_")


def strip_instance(oid: str) -> tuple[str, str]:
    """Return (metric_oid, get_or_walk_oid). Scalars keep .0 on the get list."""
    oid = oid.strip().lstrip(".")
    if oid.endswith(".0") and oid.count(".") >= 6:
        return oid[:-2], oid
    return oid, oid


def _enum_name(name: Any) -> str:
    # PyYAML treats unquoted on/off/yes/no as booleans.
    if name is True:
        return "on"
    if name is False:
        return "off"
    return str(name)


def invert_enum(enum: dict[str, Any] | None) -> dict[int, str] | None:
    if not enum:
        return None
    out: dict[int, str] = {}
    for name, num in enum.items():
        try:
            out[int(num)] = _enum_name(name)
        except (TypeError, ValueError):
            continue
    return out or None


def lookup_type(column_name: str, tag: str) -> str:
    blob = f"{column_name} {tag}"
    if GAUGE_TAG_HINT.search(blob):
        return "gauge"
    return "DisplayString"


def indexes_for_table(table_oid: str) -> list[dict[str, str]]:
    table_oid = table_oid.strip().lstrip(".")
    return TABLE_INDEXES.get(
        table_oid,
        [{"labelname": "index", "type": "gauge"}],
    )


def lookups_from_tags(metric_tags: list[dict[str, Any]] | None, indexes: list[dict[str, str]]) -> list[dict[str, Any]]:
    if not metric_tags:
        return []
    src = [i["labelname"] for i in indexes]
    out: list[dict[str, Any]] = []
    for tag in metric_tags:
        col = tag.get("column") or {}
        oid = col.get("OID")
        name = col.get("name") or tag.get("tag")
        label = tag.get("tag") or name
        if not oid or not label:
            continue
        out.append(
            {
                "labels": list(src),
                "labelname": str(label),
                "oid": str(oid).strip().lstrip("."),
                "type": lookup_type(str(name or ""), str(label)),
            }
        )
    return out


def convert_profile(path: Path) -> tuple[str, dict[str, Any], dict[str, Any]]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    mod_name = module_name_from_path(path)
    gets: list[str] = []
    walks: list[str] = []
    metrics: list[dict[str, Any]] = []
    seen_walk: set[str] = set()

    for block in data.get("metrics") or []:
        mib = block.get("MIB") or ""
        if "symbol" in block and "table" not in block:
            sym = block["symbol"] or {}
            raw_oid = str(sym.get("OID") or "").strip()
            name = str(sym.get("name") or "").strip()
            if not raw_oid or not name:
                continue
            metric_oid, get_oid = strip_instance(raw_oid)
            if get_oid not in gets:
                gets.append(get_oid)
            metric: dict[str, Any] = {
                "name": name,
                "oid": metric_oid,
                "type": "gauge",
                "help": f"{name} ({mib}) - {raw_oid}",
            }
            enum_values = invert_enum(sym.get("enum"))
            if enum_values:
                metric["enum_values"] = enum_values
            metrics.append(metric)
            continue

        table = block.get("table") or {}
        table_oid = str(table.get("OID") or "").strip().lstrip(".")
        if not table_oid:
            continue
        if table_oid not in seen_walk:
            walks.append(table_oid)
            seen_walk.add(table_oid)
        indexes = indexes_for_table(table_oid)
        lookups = lookups_from_tags(block.get("metric_tags"), indexes)
        for sym in block.get("symbols") or []:
            raw_oid = str(sym.get("OID") or "").strip().lstrip(".")
            name = str(sym.get("name") or "").strip()
            if not raw_oid or not name:
                continue
            metric = {
                "name": name,
                "oid": raw_oid,
                "type": "gauge",
                "help": f"{name} ({mib}) - {raw_oid}",
                "indexes": [dict(i) for i in indexes],
            }
            if lookups:
                metric["lookups"] = [dict(lu) for lu in lookups]
            enum_values = invert_enum(sym.get("enum"))
            if enum_values:
                metric["enum_values"] = enum_values
            metrics.append(metric)

    module: dict[str, Any] = {}
    if walks:
        module["walk"] = walks
    if gets:
        module["get"] = gets
    module["metrics"] = metrics

    index_entry = {
        "profile": path.name,
        "provider": data.get("provider"),
        "sysobjectids": list(data.get("sysobjectid") or []),
        "extends_ignored": list(data.get("extends") or []),
        "notes": "Pair with embedded if_mib via config_merge_strategy = merge",
    }
    return mod_name, module, index_entry


def oid_glob_to_regex(glob: str) -> str:
    """Kentik sysobjectid glob → regex for SuperQ-style fingerprinters (#1468)."""
    g = glob.strip().lstrip(".")
    if g.endswith(".*"):
        prefix = re.escape(g[:-2])
        return rf"^\.?{prefix}(\.[0-9]+)+$"
    return rf"^\.?{re.escape(g)}$"


def build_fingerprinters(index: dict[str, Any]) -> dict[str, Any]:
    matchers: list[dict[str, Any]] = []
    for mod_name, meta in (index.get("modules") or {}).items():
        for glob in meta.get("sysobjectids") or []:
            matchers.append(
                {
                    "label": "sysObjectID",
                    "regex": oid_glob_to_regex(str(glob)),
                    "modules": ["if_mib", str(mod_name)],
                    "comment": f"{mod_name} {glob}",
                }
            )
    # First-match wins: exact OIDs before prefix globs, then longer prefixes.
    matchers.sort(
        key=lambda m: (
            1 if r"(\.[0-9]+)+" in m["regex"] else 0,
            -len(m["regex"]),
        )
    )
    return {
        "fingerprinters": {
            "network": {
                "probe_oids": [
                    "1.3.6.1.2.1.1.2.0",  # sysObjectID
                    "1.3.6.1.2.1.1.5.0",  # sysName
                    "1.3.6.1.2.1.1.1.0",  # sysDescr
                ],
                "default_modules": ["if_mib"],
                "matchers": matchers,
            }
        }
    }


def ktranslate_name_map(path: Path) -> list[dict[str, str]]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    rows: list[dict[str, str]] = []
    for block in data.get("metrics") or []:
        symbols = []
        if "symbol" in block:
            symbols = [block["symbol"]]
        symbols.extend(block.get("symbols") or [])
        for sym in symbols:
            if not isinstance(sym, dict):
                continue
            name = str(sym.get("name") or "")
            tag = str(sym.get("tag") or "")
            if name:
                rows.append(
                    {
                        "native": name,
                        "ktranslate_tag": tag or "",
                        "kentik_snmp": f"kentik_snmp_{tag}" if tag else "",
                    }
                )
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--profiles",
        type=Path,
        default=DEFAULT_PROFILES,
        help="Directory of kentik-style profile YAML files",
    )
    ap.add_argument("--snmp-out", type=Path, default=DEFAULT_SNMP_OUT)
    ap.add_argument("--index-out", type=Path, default=DEFAULT_INDEX_OUT)
    ap.add_argument("--map-out", type=Path, default=None, help="Optional CSV/markdown name map")
    ap.add_argument("--fingerprinters-out", type=Path, default=DEFAULT_FP_OUT)
    args = ap.parse_args()

    profiles = sorted(args.profiles.glob("*.yml")) + sorted(args.profiles.glob("*.yaml"))
    if not profiles:
        print(f"ERROR: no profiles in {args.profiles}", file=sys.stderr)
        return 1

    modules: dict[str, Any] = {}
    index: dict[str, Any] = {"modules": {}}
    map_rows: list[dict[str, str]] = []

    for path in profiles:
        name, module, idx = convert_profile(path)
        modules[name] = module
        index["modules"][name] = idx
        map_rows.extend(ktranslate_name_map(path))
        print(f"converted {path.name} -> module {name} ({len(module.get('metrics') or [])} metrics)")

    snmp = {
        "auths": {
            "public_v2": {
                "community": "public",
                "security_level": "noAuthNoPriv",
                "auth_protocol": "MD5",
                "priv_protocol": "DES",
                "version": 2,
            }
        },
        "modules": modules,
    }

    header = (
        "# GENERATED by tools/snmp-profile-convert/convert.py — do not edit by hand.\n"
        "# Source profiles: kentik/snmp-profiles (Apache-2.0). See snmp/NOTICE.\n"
        "# Use with prometheus.exporter.snmp config_merge_strategy = \"merge\" so\n"
        "# embedded if_mib remains available: module = \"if_mib,<vendor>\".\n"
    )
    args.snmp_out.parent.mkdir(parents=True, exist_ok=True)
    args.snmp_out.write_text(
        header + yaml.safe_dump(snmp, sort_keys=False, default_flow_style=False),
        encoding="utf-8",
    )
    args.index_out.write_text(
        "# GENERATED sysObjectID → module index (seed for discovery.snmp).\n"
        + yaml.safe_dump(index, sort_keys=False, default_flow_style=False),
        encoding="utf-8",
    )
    fp = build_fingerprinters(index)
    args.fingerprinters_out.write_text(
        "# GENERATED. Matcher model aligns with prometheus/snmp_exporter#1468\n"
        "# (fingerprint-based module discovery). Applied here at SD time so\n"
        "# targets carry module= and auth= labels; the exporter stays stock.\n"
        + yaml.safe_dump(fp, sort_keys=False, default_flow_style=False),
        encoding="utf-8",
    )

    map_path = args.map_out or (args.snmp_out.parent / "ktranslate-name-map.md")
    lines = [
        "# Native snmp_exporter names vs ktranslate tags",
        "",
        "Mapping only — Alloy emits **native** names. ktranslate `kentik_snmp_*` stays on the existing poller.",
        "",
        "| Native metric | ktranslate `tag` | ktranslate Prom name |",
        "|---------------|------------------|----------------------|",
    ]
    seen: set[tuple[str, str]] = set()
    for row in map_rows:
        key = (row["native"], row["ktranslate_tag"])
        if key in seen:
            continue
        seen.add(key)
        lines.append(
            f"| `{row['native']}` | `{row['ktranslate_tag'] or '—'}` | `{row['kentik_snmp'] or '—'}` |"
        )
    map_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"wrote {args.snmp_out}")
    print(f"wrote {args.index_out}")
    print(f"wrote {args.fingerprinters_out}")
    print(f"wrote {map_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
