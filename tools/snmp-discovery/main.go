// Command snmp-discovery is a Prometheus-style SNMP service discovery helper.
//
// It scans CIDRs, tries named snmp.yml auths (community never written to SD),
// GETs sysObjectID/sysName/sysDescr, and stamps module= from SuperQ-style
// fingerprinters (prometheus/snmp_exporter#1468). Outputs:
//
//   - Alloy targets YAML for prometheus.exporter.snmp (encoding.from_yaml)
//   - Prometheus file_sd JSON for classic Prometheus + snmp_exporter
//
// This is a Discoverer, not an exporter. The exporter stays stock.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

func main() {
	log.SetFlags(0)
	if err := run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func run(argv []string) error {
	fs := flag.NewFlagSet("snmp-discovery", flag.ContinueOnError)
	cidrs := fs.String("cidrs", "", "comma-separated CIDRs or IPs to probe")
	port := fs.Uint("port", 161, "SNMP UDP port")
	snmpCfg := fs.String("snmp-config", "/etc/alloy/snmp-network.yml", "snmp_exporter snmp.yml (auths)")
	fpPath := fs.String("fingerprinters", "/etc/alloy/fingerprinters.yml", "fingerprint matchers (#1468)")
	fpName := fs.String("fingerprinter", "network", "fingerprinters.<name> to apply")
	authsFlag := fs.String("auths", "", "comma-separated auth names to try (default: all in snmp.yml)")
	outAlloy := fs.String("out-alloy", "/etc/alloy/snmp-targets.yml", "Alloy targets YAML")
	outSD := fs.String("out-file-sd", "/etc/alloy/snmp-file-sd.json", "Prometheus file_sd JSON")
	concurrency := fs.Int("concurrency", 8, "parallel probes")
	timeout := fs.Duration("timeout", 2*time.Second, "per-auth SNMP timeout")
	retries := fs.Int("retries", 0, "SNMP retries per auth")
	allowLarge := fs.Bool("allow-large", false, "allow CIDRs with more than 10 host bits")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if strings.TrimSpace(*cidrs) == "" {
		return fmt.Errorf("--cidrs is required")
	}

	var cidrList []string
	for _, p := range strings.Split(*cidrs, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			cidrList = append(cidrList, p)
		}
	}
	ips, err := expandCIDRs(cidrList, *allowLarge)
	if err != nil {
		return err
	}

	var authNames []string
	if s := strings.TrimSpace(*authsFlag); s != "" {
		for _, p := range strings.Split(s, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				authNames = append(authNames, p)
			}
		}
	}
	auths, err := loadAuths(*snmpCfg, authNames)
	if err != nil {
		return err
	}

	fpRaw, err := os.ReadFile(*fpPath)
	if err != nil {
		return err
	}
	var fps FingerprintersFile
	if err := yaml.Unmarshal(fpRaw, &fps); err != nil {
		return err
	}
	fp, ok := fps.Fingerprinters[*fpName]
	if !ok {
		return fmt.Errorf("fingerprinter %q not in %s", *fpName, *fpPath)
	}
	if err := fp.compile(); err != nil {
		return err
	}

	type job struct{ ip string }
	jobs := make(chan job)
	var mu sync.Mutex
	var targets []AlloyTarget
	var wg sync.WaitGroup
	workers := *concurrency
	if workers < 1 {
		workers = 1
	}
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for j := range jobs {
				res, err := probe(j.ip, uint16(*port), *timeout, *retries, auths, fp.ProbeOIDs)
				if err != nil {
					log.Printf("skip %s: %v", j.ip, err)
					continue
				}
				labels := map[string]string{
					"sysObjectID": res.SysObjectID,
					"sysName":     res.SysName,
					"sysDescr":    res.SysDescr,
				}
				mods := fp.Match(labels)
				name := targetName(res.SysName, res.Addr)
				t := AlloyTarget{
					Name:        name,
					Address:     res.Addr,
					Module:      joinModules(mods),
					Auth:        res.AuthName,
					DeviceName:  name,
					SysObjectID: res.SysObjectID,
				}
				mu.Lock()
				targets = append(targets, t)
				mu.Unlock()
				log.Printf("found %s auth=%s module=%s sysObjectID=%s", t.Address, t.Auth, t.Module, t.SysObjectID)
			}
		}()
	}
	for _, ip := range ips {
		jobs <- job{ip: ip}
	}
	close(jobs)
	wg.Wait()

	sort.Slice(targets, func(i, j int) bool {
		return targets[i].Address < targets[j].Address
	})

	if err := writeAlloyYAML(*outAlloy, targets); err != nil {
		return err
	}
	if err := writeFileSD(*outSD, targets); err != nil {
		return err
	}
	log.Printf("wrote %s and %s (%s)", *outAlloy, *outSD, fmtDiscovered(len(targets)))
	return nil
}
