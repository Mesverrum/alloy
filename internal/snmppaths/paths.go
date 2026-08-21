// Package snmppaths holds well-known filesystem locations for the Grafana
// network Alloy image. Components default to these paths; operators set the
// corresponding attributes only to load a custom library.
package snmppaths

const (
	// NetworkConfigFile is the curated snmp_exporter module library (auths +
	// modules) baked into the network image.
	NetworkConfigFile = "/etc/alloy/snmp-network.yml"

	// FingerprintersFile is the SuperQ sysObjectID → module map from the same
	// convert as NetworkConfigFile.
	FingerprintersFile = "/etc/alloy/fingerprinters.yml"

	// MIBDir is the curated trap MIB tree used by loki.source.snmptrap.
	MIBDir = "/etc/alloy/mibs"
)
