package topology

import (
	_ "embed"
	"fmt"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

//go:embed families.yaml
var defaultFamiliesYAML []byte

type family struct {
	ID           string      `yaml:"id"`
	Proto        string      `yaml:"proto"`
	Evidence     string      `yaml:"evidence"`
	Kind         string      `yaml:"kind"`
	Match        matchRule   `yaml:"match"`
	Reporter     []string    `yaml:"reporter"`
	LocalPort    []string    `yaml:"local_port"`
	Neighbor     fieldPick   `yaml:"neighbor"`
	NeighborPort fieldPick   `yaml:"neighbor_port"`
	Join         []string    `yaml:"join"`
	Session      []string    `yaml:"session"`
	RemoteAS     []string    `yaml:"remote_as"`
	LocalAS      []string    `yaml:"local_as"`
	PeerGroup    []string    `yaml:"peer_group"`
	Established  established `yaml:"established"`
}

type matchRule struct {
	NameContains    []string `yaml:"name_contains"`
	NameNotContains []string `yaml:"name_not_contains"`
}

type fieldPick struct {
	Labels              []string `yaml:"labels"`
	WhenNameContains    []string `yaml:"when_name_contains"`
	WhenNameNotContains []string `yaml:"when_name_not_contains"`
	IgnoreValues        []string `yaml:"ignore_values"`
	Lower               bool     `yaml:"lower"`
}

type established struct {
	Value         float64  `yaml:"value"`
	OrLabelEquals string   `yaml:"or_label_equals"`
	OrLabelKeys   []string `yaml:"or_label_keys"`
}

type familyFile struct {
	Families []family `yaml:"families"`
}

var (
	famOnce  sync.Once
	families []family
)

func defaultFamilies() []family {
	famOnce.Do(func() {
		var f familyFile
		if err := yaml.Unmarshal(defaultFamiliesYAML, &f); err != nil {
			panic(fmt.Errorf("prometheus.network_topology families: %w", err))
		}
		if len(f.Families) == 0 {
			panic("prometheus.network_topology families: empty catalog")
		}
		families = f.Families
	})
	return families
}

func matchFamily(name string, fams []family) *family {
	n := strings.ToLower(name)
	for i := range fams {
		if familyMatches(n, fams[i].Match) {
			return &fams[i]
		}
	}
	return nil
}

func familyMatches(nameLower string, m matchRule) bool {
	if len(m.NameContains) == 0 {
		return false
	}
	ok := false
	for _, p := range m.NameContains {
		if p != "" && strings.Contains(nameLower, strings.ToLower(p)) {
			ok = true
			break
		}
	}
	if !ok {
		return false
	}
	for _, p := range m.NameNotContains {
		if p != "" && strings.Contains(nameLower, strings.ToLower(p)) {
			return false
		}
	}
	return true
}

func label(m map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(m[k]); v != "" {
			return v
		}
	}
	return ""
}

func pickField(name string, labels map[string]string, p fieldPick) string {
	n := strings.ToLower(name)
	if len(p.WhenNameContains) > 0 {
		hit := false
		for _, w := range p.WhenNameContains {
			if w != "" && strings.Contains(n, strings.ToLower(w)) {
				hit = true
				break
			}
		}
		if !hit {
			return ""
		}
	}
	for _, w := range p.WhenNameNotContains {
		if w != "" && strings.Contains(n, strings.ToLower(w)) {
			return ""
		}
	}
	v := label(labels, p.Labels...)
	if v == "" {
		return ""
	}
	if p.Lower {
		v = strings.ToLower(v)
	}
	low := strings.ToLower(strings.TrimSpace(v))
	for _, ign := range p.IgnoreValues {
		if low == strings.ToLower(ign) {
			return ""
		}
	}
	return v
}

func pickReporter(labels map[string]string, keys []string) string {
	if v := label(labels, keys...); v != "" {
		return strings.ToLower(v)
	}
	return ""
}
