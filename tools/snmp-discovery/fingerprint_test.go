package main

import "testing"

func TestMatchNokiaSysObjectID(t *testing.T) {
	fp := Fingerprinter{
		DefaultModules: []string{"if_mib"},
		Matchers: []Matcher{
			{
				Label:   "sysObjectID",
				Regex:   `^\.?1\.3\.6\.1\.4\.1\.6527\.1\.20(\.[0-9]+)+$`,
				Modules: []string{"if_mib", "nokia_srlinux"},
			},
		},
	}
	if err := fp.compile(); err != nil {
		t.Fatal(err)
	}
	got := fp.Match(map[string]string{"sysObjectID": "1.3.6.1.4.1.6527.1.20.26"})
	if len(got) != 2 || got[0] != "if_mib" || got[1] != "nokia_srlinux" {
		t.Fatalf("got %v", got)
	}
	got = fp.Match(map[string]string{"sysObjectID": ".1.3.6.1.4.1.6527.1.20.26"})
	if len(got) != 2 || got[1] != "nokia_srlinux" {
		t.Fatalf("leading-dot: %v", got)
	}
	got = fp.Match(map[string]string{"sysObjectID": "1.3.6.1.4.1.9.1.1"})
	if len(got) != 1 || got[0] != "if_mib" {
		t.Fatalf("default: %v", got)
	}
}
