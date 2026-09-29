package topology

import (
	"encoding/hex"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	rankLLDP = 2
	rankCDP  = 3
	rankBGP  = 7
)

type sample struct {
	Name   string
	Labels map[string]string
	Value  float64
	At     time.Time
}

func relevant(name string) bool {
	n := strings.ToLower(name)
	if matchFamily(n, defaultFamilies()) != nil {
		return true
	}
	return strings.Contains(n, "lldplocport") ||
		strings.Contains(n, "lldpremportidsubtype") ||
		strings.Contains(n, "lldpremsysname") ||
		strings.Contains(n, "lldpremportid")
}

// enrichLLDP fills two gaps the walk does not.
// lldpRemLocalPortNum is an ifIndex. ifName (a lookup) or lldpLocPortId names it.
// lldpRemPortId is an OCTET STRING whose meaning depends on lldpRemPortIdSubtype.
// snmp_exporter labels those strings with the metric name (snmp_lldpRemPortId)
// and emits the subtype as snmp_lldpRemPortIdSubtype_info.
func enrichLLDP(samples []sample) []sample {
	locs := map[string]*locPort{}
	subtypes := map[string]string{}
	loc := func(key string) *locPort {
		p := locs[key]
		if p == nil {
			p = &locPort{}
			locs[key] = p
		}
		return p
	}
	for _, s := range samples {
		n := strings.ToLower(s.Name)
		dev := pickReporter(s.Labels, []string{"device_name", "src_device", "source"})
		portNum := label(s.Labels, "lldpLocPortNum", "index")
		key := dev + "|" + portNum
		switch {
		case strings.Contains(n, "lldplocportdesc"):
			if dev != "" && portNum != "" {
				loc(key).desc = label(s.Labels, "snmp_lldpLocPortDesc", "lldpLocPortDesc")
			}
		case strings.Contains(n, "lldplocportidsubtype"):
			if dev != "" && portNum != "" {
				loc(key).sub = subtypeName(s)
			}
		case strings.Contains(n, "lldplocportid"):
			if dev != "" && portNum != "" {
				loc(key).id = label(s.Labels, "snmp_lldpLocPortId", "lldpLocPortId")
			}
		case strings.Contains(n, "lldpremportidsubtype"):
			if sub := subtypeName(s); sub != "" {
				subtypes[dev+"|"+remKey(s.Labels)] = sub
			}
		}
	}

	out := make([]sample, len(samples))
	for i, s := range samples {
		labels := cloneLabels(s.Labels)
		dev := pickReporter(labels, []string{"device_name", "src_device", "source"})
		if label(labels, "ifName", "if_interface_name", "lldpLocPortDesc") == "" {
			if portNum := label(labels, "lldpRemLocalPortNum"); portNum != "" {
				if p := locs[dev+"|"+portNum]; p != nil {
					if name := localPortName(*p); name != "" {
						labels["ifName"] = name
					}
				}
			}
		}
		if sub := subtypes[dev+"|"+remKey(labels)]; sub != "" {
			for _, key := range []string{"snmp_lldpRemPortId", "lldpRemPortId"} {
				raw := labels[key]
				if raw == "" {
					continue
				}
				if decoded := decodePortValue(sub, raw); decoded != "" {
					labels[key] = decoded
					if key == "snmp_lldpRemPortId" && labels["lldpRemPortId"] == "" {
						labels["lldpRemPortId"] = decoded
					}
				}
			}
		}
		out[i] = sample{Name: s.Name, Labels: labels, Value: s.Value, At: s.At}
	}
	return out
}

type locPort struct {
	desc, id, sub string
}

func localPortName(p locPort) string {
	sub := strings.ToLower(p.sub)
	if sub == "macaddress" || sub == "3" || sub == "networkaddress" || sub == "4" {
		return p.desc
	}
	if decoded := decodePortValue(p.sub, p.id); decoded != "" {
		return decoded
	}
	return p.desc
}

func remKey(labels map[string]string) string {
	if n := label(labels, "lldpRemLocalPortNum"); n != "" || label(labels, "lldpRemIndex") != "" {
		return label(labels, "lldpRemTimeMark") + "|" + label(labels, "lldpRemLocalPortNum") + "|" + label(labels, "lldpRemIndex")
	}
	return label(labels, "index")
}

func subtypeName(s sample) string {
	if v := label(s.Labels, "snmp_lldpRemPortIdSubtype", "lldpRemPortIdSubtype", "snmp_lldpLocPortIdSubtype", "lldpLocPortIdSubtype"); v != "" {
		return v
	}
	switch int(s.Value) {
	case 3:
		return "macAddress"
	case 5:
		return "interfaceName"
	default:
		return ""
	}
}

// decodePortValue interprets an lldp*PortId label. snmp_exporter OctetString
// values arrive as 0xHEX. DisplayString MACs arrive as 6 raw bytes or 12 hex digits.
func decodePortValue(sub, raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	sub = strings.ToLower(sub)
	if strings.HasPrefix(strings.ToLower(raw), "0x") {
		if b, err := hex.DecodeString(raw[2:]); err == nil {
			if sub == "macaddress" || sub == "3" {
				if len(b) == 6 {
					return net.HardwareAddr(b).String()
				}
				return ""
			}
			if utf8.Valid(b) {
				return strings.TrimRight(string(b), "\x00")
			}
		}
	}
	if sub == "macaddress" || sub == "3" {
		if mac := formatMAC(raw); mac != "" {
			return mac
		}
		if len(raw) == 6 {
			return net.HardwareAddr([]byte(raw)).String()
		}
		return ""
	}
	if !utf8.ValidString(raw) {
		return ""
	}
	return strings.TrimRight(raw, "\x00")
}

func formatMAC(raw string) string {
	s := strings.TrimSpace(raw)
	if strings.Count(s, ":") == 5 {
		return strings.ToLower(s)
	}
	hexOnly := strings.TrimPrefix(strings.ToLower(s), "0x")
	hexOnly = strings.ReplaceAll(hexOnly, " ", "")
	if len(hexOnly) == 12 {
		if _, err := hex.DecodeString(hexOnly); err == nil {
			b, _ := hex.DecodeString(hexOnly)
			return net.HardwareAddr(b).String()
		}
	}
	if len(s) == 6 {
		return net.HardwareAddr([]byte(s)).String()
	}
	return ""
}

func cloneLabels(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// observeStats explains a reconcile. Loc-port rows are helpers: they name
// lldpRemLocalPortNum and are not expected to match a family.
type observeStats struct {
	Matched        int
	Helpers        int
	Unmatched      int
	NoReporter     int
	Noisy          int
	NoNeighbor     int
	NotEstablished int
	Self           int
	// Session peers named by the device that reports that address as its own.
	Resolved int
	// Session peers no reporter claims; the address stays as dst_device.
	Unresolved int
}

func edgesFromSamples(samples []sample) []edge {
	edges, _ := observeSamples(samples)
	return edges
}

// sessionOwners maps every address a reporter names as its own session end
// to that reporter. A peer address in the same map resolves to a device name.
// Conflicting claims keep the first reporter (sorted for determinism).
func sessionOwners(samples []sample, fams []family) map[string]string {
	owners := map[string]string{}
	for _, s := range samples {
		f := matchFamily(s.Name, fams)
		if f == nil || !strings.EqualFold(f.Kind, "session") {
			continue
		}
		src := pickReporter(s.Labels, f.Reporter)
		local := sessionAddress(label(s.Labels, f.LocalAddress...))
		if src == "" || local == "" || noisy(local) {
			continue
		}
		if prev, ok := owners[local]; ok && prev != src && prev < src {
			continue
		}
		owners[local] = src
	}
	return owners
}

// sessionAddress normalises an address label for owner matching. snmp_exporter
// renders an InetAddress column typed OctetString as "0x" + hex; a 4- or
// 16-byte blob is decoded to dotted / RFC 5952 text so it can match the
// textual peer address on the other side. Anything else is lower-cased.
func sessionAddress(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if !strings.HasPrefix(v, "0x") {
		return v
	}
	raw, err := hex.DecodeString(v[2:])
	if err != nil {
		return v
	}
	switch len(raw) {
	case 4, 16:
		if ip, ok := netip.AddrFromSlice(raw); ok {
			return ip.String()
		}
	}
	return v
}

func observeSamples(samples []sample) ([]edge, observeStats) {
	samples = enrichLLDP(samples)
	fams := defaultFamilies()
	type row struct {
		src, srcPort, dst, dstPort string
	}
	buckets := map[string]map[string]*row{}
	var edges []edge
	var st observeStats
	owners := sessionOwners(samples, fams)

	for _, s := range samples {
		f := matchFamily(s.Name, fams)
		if f == nil {
			if locHelper(s.Name) {
				st.Helpers++
			} else {
				st.Unmatched++
			}
			continue
		}
		st.Matched++
		src := pickReporter(s.Labels, f.Reporter)
		if src == "" {
			st.NoReporter++
			continue
		}
		if strings.EqualFold(f.Kind, "session") {
			if !sessionUp(s, f.Established) {
				st.NotEstablished++
				continue
			}
			peer := label(s.Labels, f.Session...)
			if peer == "" {
				st.NoNeighbor++
				continue
			}
			dst0 := sessionAddress(peer)
			dst := dst0
			if noisy(dst) {
				st.Noisy++
				continue
			}
			local := sessionAddress(label(s.Labels, f.LocalAddress...))
			if owner, ok := owners[dst]; ok {
				dst = owner
				st.Resolved++
			} else {
				st.Unresolved++
			}
			if src == dst {
				st.Self++
				continue
			}
			remoteAS := numericLabel(s.Labels, f.RemoteAS...)
			localAS := numericLabel(s.Labels, f.LocalAS...)
			peerGroup := label(s.Labels, f.PeerGroup...)
			edges = append(edges, edge{
				SrcDevice: src,
				// An IP session has addresses, not ports: our side, their side.
				SrcPort:     local,
				DstPort:     dst0,
				DstDevice:   dst,
				Proto:       f.Proto,
				LinkKind:    "ip",
				Evidence:    f.Evidence,
				SessionType: sessionType(localAS, remoteAS, peerGroup),
				RemoteAS:    remoteAS,
				PeerGroup:   peerGroup,
				Rank:        rankBGP,
			})
			continue
		}
		key := f.ID + "|" + joinKey(*f, src, s.Labels)
		b := buckets[f.ID]
		if b == nil {
			b = map[string]*row{}
			buckets[f.ID] = b
		}
		r := b[key]
		if r == nil {
			r = &row{src: src}
			b[key] = r
		}
		if port := label(s.Labels, f.LocalPort...); betterPort(r.srcPort, port) {
			r.srcPort = port
		}
		if dst := pickField(s.Name, s.Labels, f.Neighbor); dst != "" {
			r.dst = dst
		}
		if p := pickField(s.Name, s.Labels, f.NeighborPort); p != "" {
			r.dstPort = p
		}
	}

	for _, f := range fams {
		if strings.EqualFold(f.Kind, "session") {
			continue
		}
		rank := rankLLDP
		kind := "ethernet"
		if strings.EqualFold(f.Proto, "cdp") {
			rank = rankCDP
		}
		for _, r := range buckets[f.ID] {
			if r == nil || r.src == "" || r.dst == "" {
				st.NoNeighbor++
				continue
			}
			if noisy(r.dst) {
				st.Noisy++
				continue
			}
			if r.src == r.dst {
				st.Self++
				continue
			}
			edges = append(edges, edge{
				SrcDevice: r.src,
				SrcPort:   r.srcPort,
				DstDevice: r.dst,
				DstPort:   r.dstPort,
				Proto:     f.Proto,
				LinkKind:  kind,
				Evidence:  f.Evidence,
				Rank:      rank,
			})
		}
	}
	return edges, st
}

func locHelper(name string) bool {
	return strings.Contains(strings.ToLower(name), "lldplocport")
}

func betterPort(have, next string) bool {
	if next == "" {
		return false
	}
	if have == "" {
		return true
	}
	// lldpRemLocalPortNum is an ifIndex. A later sample may carry the name.
	return isDigits(have) && !isDigits(next)
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func joinKey(f family, src string, labels map[string]string) string {
	if len(f.Join) == 0 {
		return src
	}
	parts := make([]string, 0, len(f.Join))
	for _, k := range f.Join {
		if strings.EqualFold(k, "reporter") {
			parts = append(parts, src)
			continue
		}
		parts = append(parts, label(labels, k))
	}
	return strings.Join(parts, "|")
}

func sessionUp(s sample, e established) bool {
	if e.Value != 0 && s.Value == e.Value {
		return true
	}
	want := strings.ToLower(strings.TrimSpace(e.OrLabelEquals))
	if want == "" {
		return false
	}
	keys := e.OrLabelKeys
	if len(keys) == 0 {
		keys = []string{"state", "conn_state"}
	}
	for _, k := range keys {
		if strings.ToLower(strings.TrimSpace(s.Labels[k])) == want {
			return true
		}
	}
	return false
}

func numericLabel(labels map[string]string, keys ...string) string {
	v := label(labels, keys...)
	if v == "" {
		return ""
	}
	if _, err := strconv.Atoi(v); err != nil {
		return ""
	}
	return v
}

func sessionType(localAS, remoteAS, peerGroup string) string {
	if localAS != "" && remoteAS != "" {
		if localAS == remoteAS {
			return "ibgp"
		}
		return "ebgp"
	}
	g := strings.ToLower(peerGroup)
	switch {
	case strings.Contains(g, "ibgp"):
		return "ibgp"
	case strings.Contains(g, "ebgp"):
		return "ebgp"
	default:
		return ""
	}
}

func noisy(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return false
	}
	return strings.Contains(n, "phone") ||
		strings.HasPrefix(n, "ap-") ||
		strings.HasPrefix(n, "wap-") ||
		strings.HasPrefix(n, "sep")
}

func devicesFrom(edges []edge) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(n string) {
		if n == "" {
			return
		}
		if _, ok := seen[n]; ok {
			return
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	for _, e := range edges {
		add(e.SrcDevice)
		add(e.DstDevice)
	}
	return out
}
