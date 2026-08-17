package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
	"gopkg.in/yaml.v3"
)

type snmpAuth struct {
	Name      string
	Community string
	Version   gosnmp.SnmpVersion
}

type snmpFile struct {
	Auths map[string]struct {
		Community string `yaml:"community"`
		Version   int    `yaml:"version"`
	} `yaml:"auths"`
}

func loadAuths(path string, names []string) ([]snmpAuth, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg snmpFile
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	if len(names) == 0 {
		for n := range cfg.Auths {
			names = append(names, n)
		}
		sort.Strings(names)
	}
	var out []snmpAuth
	for _, n := range names {
		a, ok := cfg.Auths[n]
		if !ok {
			return nil, fmt.Errorf("auth %q not in %s", n, path)
		}
		ver := gosnmp.Version2c
		if a.Version == 1 {
			ver = gosnmp.Version1
		}
		comm := a.Community
		if comm == "" {
			comm = "public"
		}
		out = append(out, snmpAuth{Name: n, Community: comm, Version: ver})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no auths to try")
	}
	return out, nil
}

type probeResult struct {
	Addr        string
	AuthName    string
	SysObjectID string
	SysName     string
	SysDescr    string
}

func probe(addr string, port uint16, timeout time.Duration, retries int, auths []snmpAuth, oids []string) (*probeResult, error) {
	if len(oids) == 0 {
		oids = []string{"1.3.6.1.2.1.1.2.0", "1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.1.0"}
	}
	var last error
	for _, auth := range auths {
		g := &gosnmp.GoSNMP{
			Target:    addr,
			Port:      port,
			Community: auth.Community,
			Version:   auth.Version,
			Timeout:   timeout,
			Retries:   retries,
		}
		if err := g.Connect(); err != nil {
			last = err
			continue
		}
		pkt, err := g.Get(oids)
		_ = g.Conn.Close()
		if err != nil {
			last = err
			continue
		}
		if pkt == nil || len(pkt.Variables) == 0 {
			last = fmt.Errorf("empty SNMP response")
			continue
		}
		res := &probeResult{Addr: addr, AuthName: auth.Name}
		for _, v := range pkt.Variables {
			oid := normalizeOID(v.Name)
			val := stringifyPDU(v)
			switch {
			case strings.HasSuffix(oid, "1.2.1.1.2.0"):
				res.SysObjectID = normalizeOID(val)
			case strings.HasSuffix(oid, "1.2.1.1.5.0"):
				res.SysName = val
			case strings.HasSuffix(oid, "1.2.1.1.1.0"):
				res.SysDescr = val
			}
		}
		if res.SysObjectID == "" && res.SysName == "" && res.SysDescr == "" {
			last = fmt.Errorf("no sys* fields")
			continue
		}
		return res, nil
	}
	if last == nil {
		last = fmt.Errorf("no auth succeeded")
	}
	return nil, last
}

func stringifyPDU(v gosnmp.SnmpPDU) string {
	switch val := v.Value.(type) {
	case string:
		return strings.TrimSpace(val)
	case []byte:
		return strings.TrimSpace(string(val))
	default:
		if v.Value == nil {
			return ""
		}
		return strings.TrimSpace(fmt.Sprint(v.Value))
	}
}
