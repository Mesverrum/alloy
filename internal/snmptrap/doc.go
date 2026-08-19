// Package snmptrap decodes SNMP trap and inform PDUs into a structured record
// for loki.source.snmptrap.
//
// MIB name enrichment is best-effort (gosmi on optional paths). Lookup misses
// keep numeric OIDs — receive must work without a dictionary.
package snmptrap
