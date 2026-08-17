package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// AlloyTarget is what prometheus.exporter.snmp targets = encoding.from_yaml(...) expects.
type AlloyTarget struct {
	Name        string `yaml:"name" json:"name"`
	Address     string `yaml:"address" json:"address"`
	Module      string `yaml:"module" json:"module"`
	Auth        string `yaml:"auth" json:"auth"`
	DeviceName  string `yaml:"device_name" json:"device_name"`
	SysObjectID string `yaml:"sysObjectID,omitempty" json:"sysObjectID,omitempty"`
}

// FileSDGroup is Prometheus file_sd / HTTP SD.
type FileSDGroup struct {
	Targets []string          `json:"targets"`
	Labels  map[string]string `json:"labels"`
}

func writeAlloyYAML(path string, targets []AlloyTarget) error {
	if targets == nil {
		targets = []AlloyTarget{}
	}
	b, err := yaml.Marshal(targets)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func writeFileSD(path string, targets []AlloyTarget) error {
	groups := make([]FileSDGroup, 0, len(targets))
	for _, t := range targets {
		// Prometheus + snmp_exporter contract: module/auth as __param_* so
		// they become /snmp query params, not series labels. Community is
		// never written. Same named-auth model as snmp.yml `auths:`.
		labels := map[string]string{
			"__param_module": t.Module,
			"__param_auth":   t.Auth,
			"device_name":    t.DeviceName,
		}
		if t.SysObjectID != "" {
			labels["sysObjectID"] = t.SysObjectID
		}
		groups = append(groups, FileSDGroup{
			Targets: []string{t.Address},
			Labels:  labels,
		})
	}
	if groups == nil {
		groups = []FileSDGroup{}
	}
	b, err := json.MarshalIndent(groups, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, 0o644)
}

func targetName(sysName, addr string) string {
	n := strings.TrimSpace(sysName)
	if n == "" || n == addr {
		return addr
	}
	// sysName can be FQDN; take first label for the Alloy target name.
	if i := strings.IndexByte(n, '.'); i > 0 {
		n = n[:i]
	}
	return n
}

func joinModules(mods []string) string {
	return strings.Join(mods, ",")
}

func fmtDiscovered(n int) string {
	return fmt.Sprintf("%d SNMP targets", n)
}
