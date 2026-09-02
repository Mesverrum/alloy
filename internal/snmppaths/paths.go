// Package snmppaths holds well-known filesystem locations for the Grafana
// network Alloy image. Components default to these paths; operators set the
// corresponding attributes only to load a custom library.
package snmppaths

const (
	// NetworkConfigFile is the curated snmp_exporter module library (auths +
	// modules) baked into the network image. Live credentials should overlay
	// via discovery.snmp / prometheus.exporter.snmp `auths` / `auths_file`
	// (see snmp/auths.example.yml); do not vim this file on the collector.
	NetworkConfigFile = "/etc/alloy/snmp-network.yml"

	// AuthsExampleFile is documented credential YAML. Alloy does not load it.
	AuthsExampleFile = "/etc/alloy/auths.example.yml"

	// FingerprintersFile is the SuperQ sysObjectID → module map from the same
	// convert as NetworkConfigFile.
	FingerprintersFile = "/etc/alloy/fingerprinters.yml"

	// MIBDir is the curated trap MIB tree used by otelcol.receiver.snmptrap.
	MIBDir = "/etc/alloy/mibs"
)
