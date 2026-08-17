package main

import (
	"regexp"
	"strings"
)

// FingerprintersFile is the SuperQ snmp_exporter#1468 matcher model.
type FingerprintersFile struct {
	Fingerprinters map[string]Fingerprinter `yaml:"fingerprinters"`
}

type Fingerprinter struct {
	ProbeOIDs       []string  `yaml:"probe_oids"`
	DefaultModules  []string  `yaml:"default_modules"`
	Matchers        []Matcher `yaml:"matchers"`
}

type Matcher struct {
	Label   string   `yaml:"label"`
	Regex   string   `yaml:"regex"`
	Modules []string `yaml:"modules"`
	Comment string   `yaml:"comment"`
	re      *regexp.Regexp
}

func (f *Fingerprinter) compile() error {
	for i := range f.Matchers {
		re, err := regexp.Compile(f.Matchers[i].Regex)
		if err != nil {
			return err
		}
		f.Matchers[i].re = re
	}
	return nil
}

func normalizeOID(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, ".")
	s = strings.TrimPrefix(s, "iso.")
	return s
}

func (f Fingerprinter) Match(labels map[string]string) []string {
	for _, m := range f.Matchers {
		val := labels[m.Label]
		if val == "" {
			continue
		}
		cand := []string{val, normalizeOID(val), "." + normalizeOID(val)}
		ok := false
		for _, c := range cand {
			if m.re != nil && m.re.MatchString(c) {
				ok = true
				break
			}
		}
		if ok {
			return uniqueModules(m.Modules)
		}
	}
	return uniqueModules(f.DefaultModules)
}

func uniqueModules(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, m := range in {
		m = strings.TrimSpace(m)
		if m == "" {
			continue
		}
		if _, ok := seen[m]; ok {
			continue
		}
		seen[m] = struct{}{}
		out = append(out, m)
	}
	return out
}
