package main

import "testing"

func TestFilterTiersToKnownDropsMissingSidecar(t *testing.T) {
	in := ModuleTiers{
		Hot:  []string{"if_mib", "nokia_srlinux_hot", "nokia_srlinux"},
		Cold: []string{"if_mib_meta", "ip_addr"},
	}
	known := map[string]struct{}{
		"if_mib":        {},
		"if_mib_meta":   {},
		"nokia_srlinux": {},
	}
	got, dropped := filterTiersToKnown(in, known)
	if len(got.Hot) != 2 || got.Hot[0] != "if_mib" || got.Hot[1] != "nokia_srlinux" {
		t.Fatalf("hot: %v", got.Hot)
	}
	if len(got.Cold) != 1 || got.Cold[0] != "if_mib_meta" {
		t.Fatalf("cold: %v", got.Cold)
	}
	if len(dropped) != 2 {
		t.Fatalf("dropped: %v", dropped)
	}
}

func TestMatchNokiaSysObjectID(t *testing.T) {
	fp := Fingerprinter{
		DefaultModules: []string{"system_mib", "if_mib"},
		Matchers: []Matcher{
			{
				Label:   "sysObjectID",
				Regex:   `^\.?1\.3\.6\.1\.4\.1\.6527\.1\.20(\.[0-9]+)+$`,
				Modules: []string{"system_mib", "if_mib", "nokia_srlinux"},
			},
		},
	}
	if err := fp.compile(); err != nil {
		t.Fatal(err)
	}
	// Match expands legacy modules into hot+cold (if_mib → if_mib + if_mib_meta).
	got := fp.Match(map[string]string{"sysObjectID": "1.3.6.1.4.1.6527.1.20.26"})
	want := []string{"if_mib", "system_mib", "if_mib_meta", "nokia_srlinux"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
	got = fp.Match(map[string]string{"sysObjectID": ".1.3.6.1.4.1.6527.1.20.26"})
	if len(got) != 4 || got[3] != "nokia_srlinux" {
		t.Fatalf("leading-dot: %v", got)
	}
	got = fp.Match(map[string]string{"sysObjectID": "1.3.6.1.4.1.9.1.1"})
	if len(got) != 3 || got[0] != "if_mib" {
		t.Fatalf("default: %v", got)
	}
}
