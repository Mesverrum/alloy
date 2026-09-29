package topology

import (
	"strings"
	"unicode"
)

// edge is one observation. Reconcile collapses several observations of the
// same link to the highest-precedence protocol.
type edge struct {
	SrcDevice   string
	SrcPort     string
	DstDevice   string
	DstPort     string
	Proto       string
	LinkKind    string
	Direction   string
	Evidence    string
	SessionType string
	RemoteAS    string
	PeerGroup   string
	Rank        int
}

type edgeKey struct {
	srcDev, srcPort, dstDev, dstPort string
}

func (k edgeKey) less(o edgeKey) bool {
	if k.srcDev != o.srcDev {
		return k.srcDev < o.srcDev
	}
	if k.srcPort != o.srcPort {
		return k.srcPort < o.srcPort
	}
	if k.dstDev != o.dstDev {
		return k.dstDev < o.dstDev
	}
	return k.dstPort < o.dstPort
}

// portPrefixes collapses vendor long-form interface names so LLDP
// "GigabitEthernet0/1" and CDP "Gi0/1" land on one edge. Longest first.
var portPrefixes = []struct{ long, short string }{
	{"HundredGigabitEthernet", "Hu"},
	{"HundredGigE", "Hu"},
	{"FortyGigabitEthernet", "Fo"},
	{"TwentyFiveGigE", "Twe"},
	{"TenGigabitEthernet", "Te"},
	{"TwoGigabitEthernet", "Tw"},
	{"GigabitEthernet", "Gi"},
	{"FastEthernet", "Fa"},
	{"Ethernet", "Eth"},
	{"Management", "Mgmt"},
	{"Port-channel", "Po"},
	{"Loopback", "Lo"},
	{"Tunnel", "Tu"},
	{"Vlan", "Vl"},
}

func normalizePortName(name string) string {
	name = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, name)
	lower := strings.ToLower(name)
	for _, p := range portPrefixes {
		if strings.HasPrefix(lower, strings.ToLower(p.long)) {
			rest := name[len(p.long):]
			if rest == "" || (rest[0] >= '0' && rest[0] <= '9') {
				return p.short + rest
			}
		}
	}
	return name
}

func groupKey(e edge) edgeKey {
	a := edgeKey{e.SrcDevice, normalizePortName(e.SrcPort), e.DstDevice, normalizePortName(e.DstPort)}
	b := edgeKey{e.DstDevice, normalizePortName(e.DstPort), e.SrcDevice, normalizePortName(e.SrcPort)}
	if b.less(a) {
		return b
	}
	return a
}

// reconcile keeps the lowest rank (LLDP above CDP above BGP) for each
// undirected link and marks the edge bidirectional when both ends reported it.
// A one-sided BGP session keeps the reporter as src so a peer address does
// not become the device id.
func reconcile(edges []edge) []edge {
	if len(edges) == 0 {
		return nil
	}
	type group struct {
		key    edgeKey
		best   int
		sides  map[string]struct{}
		atBest []edge
	}
	groups := map[edgeKey]*group{}
	var order []edgeKey
	for _, e := range edges {
		if e.SrcDevice == "" || e.DstDevice == "" || e.SrcDevice == e.DstDevice {
			continue
		}
		k := groupKey(e)
		g := groups[k]
		if g == nil {
			g = &group{key: k, best: e.Rank, sides: map[string]struct{}{}}
			groups[k] = g
			order = append(order, k)
		}
		g.sides[e.SrcDevice] = struct{}{}
		switch {
		case e.Rank < g.best:
			g.best = e.Rank
			g.atBest = []edge{e}
		case e.Rank == g.best:
			g.atBest = append(g.atBest, e)
		}
	}

	out := make([]edge, 0, len(order))
	for _, k := range order {
		g := groups[k]
		chosen := g.atBest[0]
		for _, c := range g.atBest[1:] {
			side := c.SrcDevice == k.srcDev
			chosenSide := chosen.SrcDevice == k.srcDev
			if side && !chosenSide {
				chosen = c
			} else if side == chosenSide && c.Proto < chosen.Proto {
				chosen = c
			}
		}
		bidirectional := len(g.sides) >= 2
		keepObserver := !bidirectional && strings.EqualFold(chosen.Proto, "bgp")
		if chosen.SrcDevice != k.srcDev && !keepObserver {
			chosen.SrcDevice, chosen.DstDevice = chosen.DstDevice, chosen.SrcDevice
			chosen.SrcPort, chosen.DstPort = chosen.DstPort, chosen.SrcPort
		}
		if bidirectional {
			chosen.Direction = "bidirectional"
		} else {
			chosen.Direction = "unidirectional"
		}
		chosen.SrcPort = normalizePortName(chosen.SrcPort)
		chosen.DstPort = normalizePortName(chosen.DstPort)
		out = append(out, chosen)
	}
	return out
}
