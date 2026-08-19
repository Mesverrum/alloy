package snmpdiscovery

import "testing"

func TestMatchTiersNokia(t *testing.T) {
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
	tiers := fp.MatchTiers(map[string]string{"sysObjectID": "1.3.6.1.4.1.6527.1.20.26"})
	if len(tiers.Hot) != 1 || tiers.Hot[0] != "if_mib" {
		t.Fatalf("hot: %v", tiers.Hot)
	}
	if len(tiers.Cold) < 2 {
		t.Fatalf("cold: %v", tiers.Cold)
	}
}
