package main

import "testing"

func TestExpandCIDR32KeepsHost(t *testing.T) {
	ips, err := expandCIDRs([]string{"172.20.20.2/32"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0] != "172.20.20.2" {
		t.Fatalf(" /32 must keep the host, got %v", ips)
	}
}

func TestExpandBareIP(t *testing.T) {
	ips, err := expandCIDRs([]string{"172.20.20.3"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0] != "172.20.20.3" {
		t.Fatalf("got %v", ips)
	}
}

func TestExpandCIDR24SkipsNetworkBroadcast(t *testing.T) {
	ips, err := expandCIDRs([]string{"10.1.2.0/30"}, false)
	if err != nil {
		t.Fatal(err)
	}
	// /30 has 2 host bits (< 8) so network/broadcast are kept — that is
	// intentional so tiny lab CIDRs are not emptied. /24+ skip them.
	if len(ips) != 4 {
		t.Fatalf("got %v", ips)
	}
	ips, err = expandCIDRs([]string{"10.9.9.0/24"}, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range ips {
		if ip == "10.9.9.0" || ip == "10.9.9.255" {
			t.Fatalf("network/broadcast leaked: %s", ip)
		}
	}
	if len(ips) != 254 {
		t.Fatalf("want 254 hosts, got %d", len(ips))
	}
}

func TestExpandRejectsLargeCIDR(t *testing.T) {
	_, err := expandCIDRs([]string{"10.0.0.0/16"}, false)
	if err == nil {
		t.Fatal("expected --allow-large error")
	}
}
