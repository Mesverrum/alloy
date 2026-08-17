package main

import (
	"fmt"
	"net"
	"strings"
)

func expandCIDRs(cidrs []string, allowLarge bool) ([]string, error) {
	var ips []string
	for _, raw := range cidrs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if !strings.Contains(raw, "/") {
			ip := net.ParseIP(raw)
			if ip == nil || ip.To4() == nil {
				return nil, fmt.Errorf("invalid IP or CIDR: %s", raw)
			}
			ips = append(ips, ip.To4().String())
			continue
		}
		_, ipnet, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, err
		}
		ones, bits := ipnet.Mask.Size()
		hostBits := bits - ones
		if hostBits > 10 && !allowLarge {
			return nil, fmt.Errorf("CIDR %s has %d host bits; pass --allow-large to scan", raw, hostBits)
		}
		for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
			addr := append(net.IP(nil), ip...)
			if addr.To4() == nil {
				continue
			}
			s := addr.To4().String()
			if hostBits >= 8 && (isNetwork(ipnet, addr) || isBroadcast(ipnet, addr)) {
				continue
			}
			ips = append(ips, s)
		}
	}
	return uniqueStrings(ips), nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func isNetwork(n *net.IPNet, ip net.IP) bool {
	return n.IP.Equal(ip)
}

func isBroadcast(n *net.IPNet, ip net.IP) bool {
	bcast := make(net.IP, len(n.IP))
	copy(bcast, n.IP)
	for i := range bcast {
		bcast[i] |= ^n.Mask[i]
	}
	return bcast.Equal(ip)
}

func uniqueStrings(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
