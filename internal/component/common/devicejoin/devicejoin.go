// Package devicejoin maps a packet/log source IP (or hostname) to a discovery
// identity (device_name). Used by loki.source.snmptrap, loki.source.syslog,
// and otelcol.receiver.netflow.
package devicejoin

import (
	"net/netip"
	"strings"

	"github.com/grafana/alloy/internal/component/discovery"
)

// Identity is one catalog device. Address is the primary (scraped) IP.
type Identity struct {
	DeviceName string
	Address    string
	Group      string
}

// Index looks up identities by any known address, including collapsed aliases,
// and by device_name (syslog hostname).
type Index struct {
	byAddr map[string]Identity
	byName map[string]Identity
}

// NewIndex builds an address → identity map from discovery targets.
// It indexes `address` and comma-separated `snmp_aliases`.
func NewIndex(targets []discovery.Target) *Index {
	idx := &Index{
		byAddr: make(map[string]Identity, len(targets)),
		byName: make(map[string]Identity, len(targets)),
	}
	if len(targets) == 0 {
		return idx
	}
	for _, t := range targets {
		addr, _ := t.Get("address")
		dn, _ := t.Get("device_name")
		if dn == "" {
			dn, _ = t.Get("name")
		}
		group, _ := t.Get("snmp_group")
		id := Identity{
			DeviceName: strings.TrimSpace(dn),
			Address:    canon(addr),
			Group:      strings.TrimSpace(group),
		}
		if id.DeviceName == "" && id.Address == "" {
			continue
		}
		if id.Address != "" {
			idx.byAddr[id.Address] = id
		}
		if aliases, ok := t.Get("snmp_aliases"); ok {
			for _, a := range strings.Split(aliases, ",") {
				if c := canon(a); c != "" {
					idx.byAddr[c] = id
				}
			}
		}
		if id.DeviceName != "" {
			idx.byName[strings.ToLower(id.DeviceName)] = id
		}
	}
	return idx
}

// Len is the number of indexed addresses (primary + aliases).
func (i *Index) Len() int {
	if i == nil {
		return 0
	}
	return len(i.byAddr)
}

// Lookup returns the identity for the first matching IP (UDP source, then
// agent address, etc.).
func (i *Index) Lookup(ips ...string) (Identity, bool) {
	if i == nil || len(i.byAddr) == 0 {
		return Identity{}, false
	}
	for _, raw := range ips {
		if c := canon(raw); c != "" {
			if id, ok := i.byAddr[c]; ok {
				return id, true
			}
		}
	}
	for _, raw := range ips {
		k := strings.ToLower(strings.TrimSpace(raw))
		if k == "" {
			continue
		}
		if id, ok := i.byName[k]; ok {
			return id, true
		}
	}
	return Identity{}, false
}

func canon(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if host, _, ok := strings.Cut(raw, "%"); ok {
		raw = host
	}
	addr, err := netip.ParseAddr(strings.Trim(raw, "[]"))
	if err != nil {
		return raw
	}
	return addr.String()
}
