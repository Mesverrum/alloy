# snmp-profile-convert

Convert [kentik/snmp-profiles](https://github.com/kentik/snmp-profiles) YAML (numeric OIDs) to snmp_exporter **runtime** `snmp.yml` modules. No MIB compiler.

```bash
python3 tools/snmp-profile-convert/convert.py
# writes snmp/snmp-network.yml, snmp/fingerprinters.yml, snmp/sysobjectid-index.yaml
```

See [docs/network-snmp.md](../../docs/network-snmp.md).
