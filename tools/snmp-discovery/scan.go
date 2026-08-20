package main

import (
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"
)

type scanParams struct {
	snmpCfg      string
	fpPath       string
	defaultFP    string
	outAlloy     string
	outSD        string
	concurrency  int
	timeout      time.Duration
	retries      int
	defaultPort  uint16
	catalog      *catalog
	ping         bool
	pingTimeout  time.Duration
	misses       int // consecutive discovery cycles with no response before drop; <=0 = never
	statePath    string
	pingFilter   func([]string) ([]string, error)
	walkNeighbor func(addr string, port uint16, auths []snmpAuth) []string
	// knownModules, when set, is the snmp.yml module catalog used to drop
	// fingerprinter names that do not exist. runScan loads it from snmpCfg
	// when this field is nil.
	knownModules map[string]struct{}
}

type probeJob struct {
	ip    string
	group DiscoveryGroup
	auths []snmpAuth
	fp    Fingerprinter
	port  uint16
}

type groupRuntime struct {
	group DiscoveryGroup
	auths []snmpAuth
	fp    Fingerprinter
	port  uint16
}

func runScan(cfg DiscoveryFile, p scanParams) error {
	start := time.Now()
	fpRaw, err := loadFingerprinters(p.fpPath)
	if err != nil {
		return err
	}
	if p.knownModules == nil && strings.TrimSpace(p.snmpCfg) != "" {
		names, err := loadModuleNames(p.snmpCfg)
		if err != nil {
			log.Printf("warn: snmp.yml module catalog unavailable; emitting fingerprinter names unchecked path=%s err=%v", p.snmpCfg, err)
		} else if len(names) > 0 {
			p.knownModules = names
		}
	}

	prev := []AlloyTarget{}
	if p.catalog != nil {
		prev, _ = p.catalog.snapshot()
	}

	rts, err := loadGroupRuntimes(cfg, p, fpRaw)
	if err != nil {
		// Failed before probes — do not touch catalog / miss counters / on-disk SD.
		return err
	}

	jobs, claimed, sweepN, pingN, err := planInitialJobs(rts, p, prev)
	if err != nil {
		return err
	}
	found := probeAll(jobs, p)

	crawlJobs := planCrawlJobs(rts, p, prev, found, claimed)
	if len(crawlJobs) > 0 {
		found = append(found, probeAll(crawlJobs, p)...)
	}

	ignoreAddrs := ignoredAddresses(cfg.Overrides)
	found = applyOverrides(found, cfg.Overrides)
	found = dedupeTargets(found)
	uniquifyNames(found)
	sort.Slice(found, func(i, k int) bool {
		return found[i].Address < found[k].Address
	})

	// Successful complete pass only — merge misses + publish atomically.
	published := found
	dropped := 0
	if p.catalog != nil {
		beforeAddrs := map[string]struct{}{}
		for _, e := range p.catalog.snapshotEntries() {
			beforeAddrs[e.Target.Address] = struct{}{}
		}
		published = p.catalog.mergeFound(found, time.Now().UTC(), p.misses)
		if n := p.catalog.dropAddresses(ignoreAddrs); n > 0 {
			log.Printf("ignore override removed %d catalog entries", n)
			published, _ = p.catalog.snapshot()
		}
		for addr := range beforeAddrs {
			still := false
			for _, t := range published {
				if t.Address == addr {
					still = true
					break
				}
			}
			if !still {
				dropped++
			}
		}
		sort.Slice(published, func(i, k int) bool {
			return published[i].Address < published[k].Address
		})
		uniquifyNames(published)
	}

	if err := publishCatalog(p, published); err != nil {
		return err
	}
	log.Printf("scan %s in %s (sweep %d ping_up %d snmp %d catalog %d dropped %d)",
		fmtDiscovered(len(found)), time.Since(start).Truncate(time.Millisecond),
		sweepN, pingN, len(found), len(published), dropped)
	return nil
}

// publishCatalog writes YAML + file_sd + state via temp+rename. Call only after
// a complete successful probe pass (never on partial/error paths).
//
// Alloy staggered scrapes: --out-alloy is the hot catalog; siblings
// *-cold.yml and *-topology.yml are written beside it (empty list when no modules).
func publishCatalog(p scanParams, published []AlloyTarget) error {
	if p.outAlloy != "" {
		if err := writeAlloyYAML(p.outAlloy, tierTargets(published, "hot")); err != nil {
			return err
		}
		if err := writeAlloyYAML(tierSiblingPath(p.outAlloy, "-cold"), tierTargets(published, "cold")); err != nil {
			return err
		}
		if err := writeAlloyYAML(tierSiblingPath(p.outAlloy, "-topology"), tierTargets(published, "topology")); err != nil {
			return err
		}
	}
	if err := writeFileSD(p.outSD, published); err != nil {
		return err
	}
	if p.catalog != nil {
		if err := writeCatalogState(p.statePath, p.catalog); err != nil {
			return err
		}
	}
	return nil
}

func tierSiblingPath(path, suffix string) string {
	switch {
	case strings.HasSuffix(path, ".yml"):
		return strings.TrimSuffix(path, ".yml") + suffix + ".yml"
	case strings.HasSuffix(path, ".yaml"):
		return strings.TrimSuffix(path, ".yaml") + suffix + ".yaml"
	default:
		return path + suffix
	}
}

// tierTargets projects a catalog into a single-module YAML list for one scrape tier.
// Target names are suffixed (-hot/-cold/-topology) so concurrent prometheus.exporter.snmp
// instances do not collide on the same `name` (device_name stays the friendly sysName).
func tierTargets(in []AlloyTarget, tier string) []AlloyTarget {
	out := make([]AlloyTarget, 0, len(in))
	for _, t := range in {
		mod := t.Module
		switch tier {
		case "cold":
			mod = t.ModuleCold
		case "topology":
			mod = t.ModuleTopology
		}
		if strings.TrimSpace(mod) == "" {
			continue
		}
		name := strings.TrimSpace(t.Name)
		if name == "" {
			name = t.Address
		}
		out = append(out, AlloyTarget{
			Name:        name + "-" + tier,
			Address:     t.Address,
			Module:      mod,
			Auth:        t.Auth,
			DeviceName:  t.DeviceName,
			SysObjectID: t.SysObjectID,
			SnmpGroup:   t.SnmpGroup,
		})
	}
	return out
}

func loadGroupRuntimes(cfg DiscoveryFile, p scanParams, fps FingerprintersFile) ([]groupRuntime, error) {
	var rts []groupRuntime
	for _, g := range cfg.Groups {
		fpName := g.Fingerprinter
		if fpName == "" {
			fpName = p.defaultFP
		}
		fp, ok := fps.Fingerprinters[fpName]
		if !ok {
			return nil, fmt.Errorf("group %q: fingerprinter %q not in %s", g.Name, fpName, p.fpPath)
		}
		if err := fp.compile(); err != nil {
			return nil, fmt.Errorf("group %q fingerprinter: %w", g.Name, err)
		}
		auths, err := loadAuths(p.snmpCfg, g.Auths)
		if err != nil {
			return nil, fmt.Errorf("group %q: %w", g.Name, err)
		}
		port := g.Port
		if port == 0 {
			port = p.defaultPort
		}
		rts = append(rts, groupRuntime{group: g, auths: auths, fp: fp, port: port})
	}
	return rts, nil
}

func planInitialJobs(rts []groupRuntime, p scanParams, prev []AlloyTarget) ([]probeJob, map[string]string, int, int, error) {
	claimed := map[string]string{}
	var jobs []probeJob
	sweepN, pingN := 0, 0
	for _, rt := range rts {
		g := rt.group
		mode := groupMode(g)
		var ips []string
		if mode == modeSweep || mode == modeBoth {
			raw, err := expandCIDRs(g.CIDRs, g.AllowLarge)
			if err != nil {
				return nil, nil, 0, 0, fmt.Errorf("group %q: %w", g.Name, err)
			}
			raw, err = filterExcluded(raw, g.Exclude)
			if err != nil {
				return nil, nil, 0, 0, fmt.Errorf("group %q exclude: %w", g.Name, err)
			}
			sweepN += len(raw)
			if groupUsesPing(g, p.ping) {
				alive, err := filterPing(p, raw)
				if err != nil {
					return nil, nil, 0, 0, fmt.Errorf("group %q ping: %w", g.Name, err)
				}
				pingN += len(alive)
				ips = append(ips, alive...)
			} else {
				pingN += len(raw)
				ips = append(ips, raw...)
			}
		}
		// Always re-probe seeds + catalog for this group (Zabbix-style: ICMP
		// does not gate known inventory). Ping only filters *new* CIDR candidates.
		ips = append(ips, seedIPs(g, prev)...)
		for _, ip := range uniqueStrings(ips) {
			if owner, ok := claimed[ip]; ok {
				log.Printf("skip %s: already claimed by group %q (not %q)", ip, owner, g.Name)
				continue
			}
			claimed[ip] = g.Name
			jobs = append(jobs, probeJob{ip: ip, group: g, auths: rt.auths, fp: rt.fp, port: rt.port})
		}
	}
	return jobs, claimed, sweepN, pingN, nil
}

func seedIPs(g DiscoveryGroup, prev []AlloyTarget) []string {
	var ips []string
	for _, s := range g.Seeds {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		ips = append(ips, mustCanonIP(s))
	}
	for _, t := range prev {
		if t.SnmpGroup == g.Name && t.Address != "" {
			ips = append(ips, mustCanonIP(t.Address))
		}
	}
	return ips
}

func planCrawlJobs(rts []groupRuntime, p scanParams, prev, found []AlloyTarget, claimed map[string]string) []probeJob {
	walk := p.walkNeighbor
	if walk == nil {
		walk = func(addr string, port uint16, auths []snmpAuth) []string {
			return walkNeighbors(addr, port, auths, p.timeout)
		}
	}
	seeds := append([]AlloyTarget{}, found...)
	seeds = append(seeds, prev...)
	var jobs []probeJob
	for _, rt := range rts {
		g := rt.group
		mode := groupMode(g)
		if mode != modeCrawl && mode != modeBoth {
			continue
		}
		var walkFrom []string
		for _, s := range g.Seeds {
			s = strings.TrimSpace(s)
			if s != "" {
				walkFrom = append(walkFrom, s)
			}
		}
		for _, t := range seeds {
			if t.SnmpGroup != "" && t.SnmpGroup != g.Name {
				continue
			}
			if t.Address != "" {
				walkFrom = append(walkFrom, t.Address)
			}
		}
		for _, addr := range uniqueStrings(walkFrom) {
			addr = mustCanonIP(addr)
			for _, ip := range walk(addr, rt.port, rt.auths) {
				ip = mustCanonIP(ip)
				if ip == addr {
					continue
				}
				if !allowNeighbor(ip, g.CIDRs, g.Exclude) {
					continue
				}
				if _, ok := claimed[ip]; ok {
					continue
				}
				claimed[ip] = g.Name
				jobs = append(jobs, probeJob{ip: ip, group: g, auths: rt.auths, fp: rt.fp, port: rt.port})
			}
		}
	}
	return jobs
}

func filterPing(p scanParams, ips []string) ([]string, error) {
	if len(ips) == 0 {
		return ips, nil
	}
	if p.pingFilter != nil {
		return p.pingFilter(ips)
	}
	if !p.ping {
		return ips, nil
	}
	return icmpAlive(ips, p.pingTimeout)
}

func probeAll(jobs []probeJob, p scanParams) []AlloyTarget {
	if len(jobs) == 0 {
		return nil
	}
	workers := p.concurrency
	if workers < 1 {
		workers = 1
	}
	ch := make(chan probeJob)
	var mu sync.Mutex
	var targets []AlloyTarget
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for j := range ch {
				res, err := probe(j.ip, j.port, p.timeout, p.retries, j.auths, j.fp.ProbeOIDs)
				if err != nil {
					continue
				}
				labels := map[string]string{
					"sysObjectID": res.SysObjectID,
					"sysName":     res.SysName,
					"sysDescr":    res.SysDescr,
				}
				tiers, dropped := filterTiersToKnown(j.fp.MatchTiers(labels), p.knownModules)
				if len(dropped) > 0 {
					log.Printf("warn: dropping fingerprinter modules missing from snmp.yml address=%s dropped=%v", j.ip, dropped)
				}
				name, deviceName := targetNames(res.SysName, res.Addr)
				t := AlloyTarget{
					Name:           name,
					Address:        mustCanonIP(res.Addr),
					Module:         joinModules(tiers.Hot),
					ModuleCold:     joinModules(tiers.Cold),
					ModuleTopology: joinModules(tiers.Topology),
					Auth:           res.AuthName,
					DeviceName:     deviceName,
					SysObjectID:    res.SysObjectID,
					SnmpGroup:      j.group.Name,
				}
				mu.Lock()
				targets = append(targets, t)
				mu.Unlock()
				log.Printf("found %s group=%s auth=%s hot=%s cold=%s topo=%s sysObjectID=%s",
					t.Address, t.SnmpGroup, t.Auth, t.Module, t.ModuleCold, t.ModuleTopology, t.SysObjectID)
			}
		}()
	}
	for _, j := range jobs {
		ch <- j
	}
	close(ch)
	wg.Wait()
	return targets
}

func dedupeTargets(in []AlloyTarget) []AlloyTarget {
	seen := map[string]struct{}{}
	out := make([]AlloyTarget, 0, len(in))
	for _, t := range in {
		if _, ok := seen[t.Address]; ok {
			continue
		}
		seen[t.Address] = struct{}{}
		out = append(out, t)
	}
	return out
}

// expandJobs is the sweep-only planner used by tests (first-group-wins).
func expandJobs(cfg DiscoveryFile, p scanParams, fps FingerprintersFile) ([]probeJob, error) {
	rts, err := loadGroupRuntimes(cfg, p, fps)
	if err != nil {
		return nil, err
	}
	p.ping = false
	p.pingFilter = func(ips []string) ([]string, error) { return ips, nil }
	jobs, _, _, _, err := planInitialJobs(rts, p, nil)
	return jobs, err
}
