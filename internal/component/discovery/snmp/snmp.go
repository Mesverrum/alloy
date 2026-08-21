// Package snmp implements the discovery.snmp component — Prometheus-shaped
// SNMP service discovery (CIDR sweep / LLDP crawl + named auths + fingerprinters).
package snmp

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/grafana/alloy/internal/component"
	"github.com/grafana/alloy/internal/component/discovery"
	"github.com/grafana/alloy/internal/featuregate"
	"github.com/grafana/alloy/internal/service/livedebugging"
	"github.com/grafana/alloy/internal/snmpdiscovery"
	"github.com/grafana/alloy/internal/snmppaths"
	"github.com/grafana/alloy/syntax/alloytypes"
)

func init() {
	component.Register(component.Registration{
		Name:      "discovery.snmp",
		Stability: featuregate.StabilityExperimental,
		Args:      Arguments{},
		Exports:   discovery.Exports{},

		Build: func(opts component.Options, args component.Arguments) (component.Component, error) {
			return New(opts, args.(Arguments))
		},
	})
}

// Arguments configures discovery.snmp.
type Arguments struct {
	// RefreshInterval is how often to re-scan. Prefer hours–days in production.
	RefreshInterval time.Duration `alloy:"refresh_interval,attr,optional"`

	// Tier selects which scrape modules to export: "hot", "cold", "topology",
	// or "all" (default) — one target per device per non-empty tier.
	Tier string `alloy:"tier,attr,optional"`

	SnmpConfig     string                    `alloy:"snmp_config,attr,optional"`
	Auths          alloytypes.OptionalSecret `alloy:"auths,attr,optional"`
	AuthsFile      string                    `alloy:"auths_file,attr,optional"`
	Fingerprinters string                    `alloy:"fingerprinters,attr,optional"`
	Fingerprinter  string        `alloy:"fingerprinter,attr,optional"`
	ConfigPath     string        `alloy:"config_path,attr,optional"`
	OverridesPath  string        `alloy:"overrides_path,attr,optional"`
	Concurrency    int           `alloy:"concurrency,attr,optional"`
	Timeout        time.Duration `alloy:"timeout,attr,optional"`
	Retries        int           `alloy:"retries,attr,optional"`
	Port           int           `alloy:"port,attr,optional"`
	Ping           bool          `alloy:"ping,attr,optional"`
	PingTimeout    time.Duration `alloy:"ping_timeout,attr,optional"`
	Misses         int           `alloy:"misses,attr,optional"`
	StatePath      string        `alloy:"state_path,attr,optional"`
	AllowLarge     bool          `alloy:"allow_large,attr,optional"`
	// AllowDuplicateSysName keeps every SNMP address when several share a
	// sysName (cloned IoT hostnames). Default false: one identity per
	// hostname, lowest IP wins.
	AllowDuplicateSysName bool `alloy:"allow_duplicate_sysname,attr,optional"`

	// Inline groups (Fleet-friendly). Ignored when config_path is set for the
	// group list; inline overrides still append.
	Groups    []GroupArguments    `alloy:"group,block,optional"`
	Overrides []OverrideArguments `alloy:"override,block,optional"`
}

// GroupArguments is one CIDR-scoped discovery group (no community strings).
type GroupArguments struct {
	Name          string   `alloy:"name,attr"`
	CIDRs         []string `alloy:"cidrs,attr,optional"`
	Exclude       []string `alloy:"exclude,attr,optional"`
	Seeds         []string `alloy:"seeds,attr,optional"`
	Auths         []string `alloy:"auths,attr"`
	Fingerprinter string   `alloy:"fingerprinter,attr,optional"`
	Port          int      `alloy:"port,attr,optional"`
	AllowLarge    bool     `alloy:"allow_large,attr,optional"`
	Mode          string   `alloy:"mode,attr,optional"`
	Ping          *bool    `alloy:"ping,attr,optional"`
}

// OverrideArguments pins or ignores a device by SNMP address.
type OverrideArguments struct {
	Address        string `alloy:"address,attr"`
	Ignore         bool   `alloy:"ignore,attr,optional"`
	Name           string `alloy:"name,attr,optional"`
	Module         string `alloy:"module,attr,optional"`
	ModuleHot      string `alloy:"module_hot,attr,optional"`
	ModuleCold     string `alloy:"module_cold,attr,optional"`
	ModuleTopology string `alloy:"module_topology,attr,optional"`
	Auth           string `alloy:"auth,attr,optional"`
}

// DefaultArguments holds defaults for discovery.snmp.
var DefaultArguments = Arguments{
	RefreshInterval: 15 * time.Minute,
	Tier:            "all",
	SnmpConfig:      snmppaths.NetworkConfigFile,
	Fingerprinters:  snmppaths.FingerprintersFile,
	Fingerprinter:   "network",
	Concurrency:     8,
	Timeout:         2 * time.Second,
	Retries:         0,
	Port:            161,
	Ping:            true,
	PingTimeout:     400 * time.Millisecond,
	Misses:          3,
}

// SetToDefault implements syntax.Defaulter.
func (args *Arguments) SetToDefault() {
	*args = DefaultArguments
}

// Validate implements syntax.Validator.
func (args Arguments) Validate() error {
	if strings.TrimSpace(args.SnmpConfig) == "" {
		return fmt.Errorf("snmp_config is empty (omit it to use %s)", snmppaths.NetworkConfigFile)
	}
	if strings.TrimSpace(args.Auths.Value) != "" && strings.TrimSpace(args.AuthsFile) != "" {
		return fmt.Errorf("auths and auths_file are mutually exclusive")
	}
	if strings.TrimSpace(args.ConfigPath) == "" && len(args.Groups) == 0 {
		return fmt.Errorf("provide config_path or at least one group block")
	}
	switch strings.ToLower(strings.TrimSpace(args.Tier)) {
	case "", "all", "hot", "cold", "topology":
	default:
		return fmt.Errorf("tier must be hot, cold, topology, or all")
	}
	if args.RefreshInterval <= 0 {
		return fmt.Errorf("refresh_interval must be > 0")
	}
	if args.Concurrency <= 0 {
		return fmt.Errorf("concurrency must be > 0")
	}
	if args.Timeout <= 0 {
		return fmt.Errorf("timeout must be > 0")
	}
	if args.PingTimeout <= 0 {
		return fmt.Errorf("ping_timeout must be > 0")
	}
	if args.Port < 1 || args.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	if args.Retries < 0 {
		return fmt.Errorf("retries must be >= 0")
	}
	if args.Misses < 0 {
		return fmt.Errorf("misses must be >= 0")
	}
	return nil
}

// Component implements discovery.snmp.
type Component struct {
	opts               component.Options
	log                *slog.Logger
	m                  *metrics
	debugDataPublisher livedebugging.DebugDataPublisher

	argsMu sync.RWMutex
	args   Arguments

	cat *snmpdiscovery.Catalog

	scanMu      sync.Mutex
	argsUpdates chan Arguments

	healthMu sync.RWMutex
	health   component.Health
}

var (
	_ component.Component       = (*Component)(nil)
	_ component.HealthComponent = (*Component)(nil)
	_ component.LiveDebugging   = (*Component)(nil)
)

// New constructs a discovery.snmp component.
func New(opts component.Options, args Arguments) (*Component, error) {
	debugDataPublisher, err := opts.GetServiceData(livedebugging.ServiceName)
	if err != nil {
		return nil, err
	}

	c := &Component{
		opts:               opts,
		log:                opts.Logger,
		m:                  newMetrics(opts.Registerer),
		debugDataPublisher: debugDataPublisher.(livedebugging.DebugDataPublisher),
		args:               args,
		cat:                snmpdiscovery.NewCatalog(),
		argsUpdates:        make(chan Arguments, 1),
		health: component.Health{
			Health:     component.HealthTypeUnknown,
			Message:    "component started",
			UpdateTime: time.Now(),
		},
	}
	if err := c.applyArgs(args); err != nil {
		return nil, err
	}
	return c, nil
}

// Run implements component.Component.
func (c *Component) Run(ctx context.Context) error {
	if err := c.scanOnce(); err != nil {
		c.log.Warn("initial SNMP discovery failed", "err", err)
	}

	c.argsMu.RLock()
	interval := c.args.RefreshInterval
	c.argsMu.RUnlock()
	t := time.NewTicker(interval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case a := <-c.argsUpdates:
			if err := c.applyArgs(a); err != nil {
				c.setHealth(component.HealthTypeUnhealthy, fmt.Sprintf("invalid configuration: %s", err))
				c.log.Warn("invalid discovery.snmp update", "err", err)
				continue
			}
			t.Reset(a.RefreshInterval)
			if err := c.scanOnce(); err != nil {
				c.log.Warn("SNMP discovery failed after update", "err", err)
			}
		case <-t.C:
			if err := c.scanOnce(); err != nil {
				c.log.Warn("SNMP discovery failed", "err", err)
			}
		}
	}
}

// Update implements component.Component.
func (c *Component) Update(args component.Arguments) error {
	a := args.(Arguments)
	select {
	case c.argsUpdates <- a:
	default:
		select {
		case <-c.argsUpdates:
		default:
		}
		c.argsUpdates <- a
	}
	return nil
}

// CurrentHealth implements component.HealthComponent.
func (c *Component) CurrentHealth() component.Health {
	c.healthMu.RLock()
	defer c.healthMu.RUnlock()
	return c.health
}

// LiveDebugging implements component.LiveDebugging.
func (c *Component) LiveDebugging() {}

func (c *Component) setHealth(kind component.HealthType, msg string) {
	c.healthMu.Lock()
	defer c.healthMu.Unlock()
	c.health = component.Health{
		Health:     kind,
		Message:    msg,
		UpdateTime: time.Now(),
	}
}

func (c *Component) applyArgs(args Arguments) error {
	if err := args.Validate(); err != nil {
		return err
	}
	c.argsMu.Lock()
	c.args = args
	c.argsMu.Unlock()

	if sp := strings.TrimSpace(args.StatePath); sp != "" {
		if entries, err := snmpdiscovery.ReadCatalogState(sp); err == nil && len(entries) > 0 {
			c.cat.LoadEntries(entries)
			c.log.Info("loaded SNMP discovery catalog state", "path", sp, "entries", len(entries))
		} else if err != nil {
			c.log.Debug("no SNMP discovery catalog state yet", "path", sp, "err", err)
		}
	}
	return nil
}

func (c *Component) scanOnce() error {
	if !c.scanMu.TryLock() {
		c.m.skipped.Inc()
		c.log.Info("SNMP discovery scan still running; skip this tick")
		return nil
	}
	defer c.scanMu.Unlock()
	c.m.scanInFlight.Set(1)
	defer c.m.scanInFlight.Set(0)

	c.argsMu.RLock()
	args := c.args
	c.argsMu.RUnlock()

	cfg, err := buildConfig(args)
	if err != nil {
		c.m.scans.Inc()
		c.m.failures.Inc()
		c.setHealth(component.HealthTypeUnhealthy, fmt.Sprintf("scan failed: %s", err))
		return err
	}

	overlay, err := snmpdiscovery.ResolveAuthsOverlay(args.Auths.Value, args.AuthsFile)
	if err != nil {
		c.m.scans.Inc()
		c.m.failures.Inc()
		c.setHealth(component.HealthTypeUnhealthy, fmt.Sprintf("auths overlay: %s", err))
		return err
	}

	p := snmpdiscovery.ScanParams{
		SnmpCfg:               args.SnmpConfig,
		AuthsOverlay:          overlay,
		FpPath:                args.Fingerprinters,
		DefaultFP:             args.Fingerprinter,
		Concurrency:           args.Concurrency,
		Timeout:               args.Timeout,
		Retries:               args.Retries,
		DefaultPort:           uint16(args.Port),
		Catalog:               c.cat,
		Ping:                  args.Ping,
		PingTimeout:           args.PingTimeout,
		Misses:                args.Misses,
		StatePath:             args.StatePath,
		Logger:                c.log,
		AllowDuplicateSysName: args.AllowDuplicateSysName,
		Observer:              probeHook{m: c.m},
	}

	published, stats, err := snmpdiscovery.Discover(cfg, p)
	c.m.scans.Inc()
	if err != nil {
		c.m.failures.Inc()
		c.setHealth(component.HealthTypeUnhealthy, fmt.Sprintf("scan failed: %s", err))
		return err
	}

	c.m.duration.Observe(stats.Duration.Seconds())
	c.m.devices.Set(float64(stats.Catalog))
	c.m.sweep.Set(float64(stats.Sweep))
	c.m.pingUp.Set(float64(stats.PingUp))
	dead := stats.Sweep - stats.PingUp
	if dead < 0 {
		dead = 0
	}
	c.m.pingDead.Set(float64(dead))
	c.m.probeOK.Set(float64(stats.ProbeSuccess))
	c.m.probeErrs.Set(float64(stats.ProbeErrors))
	if stats.Dropped > 0 {
		c.m.dropped.Add(float64(stats.Dropped))
	}
	c.m.dedupes.Set(float64(stats.Dedupes))
	if stats.Dedupes > 0 {
		c.m.dedupesTot.Add(float64(stats.Dedupes))
	}

	tiered := expandTiers(published, args.Tier)
	targets := make([]discovery.Target, 0, len(tiered))
	for _, tt := range tiered {
		targets = append(targets, toDiscoveryTarget(tt.target, tt.tier))
	}
	c.m.targets.Set(float64(len(targets)))
	c.opts.OnStateChange(discovery.Exports{Targets: targets})
	c.setHealth(component.HealthTypeHealthy, fmt.Sprintf("discovered %d devices, %d targets, %d dedupes", len(published), len(targets), stats.Dedupes))
	c.log.Info("SNMP discovery refresh",
		"targets", len(targets),
		"devices", len(published),
		"duration", stats.Duration,
		"dropped", stats.Dropped,
		"dedupes", stats.Dedupes,
		"probe_success", stats.ProbeSuccess,
		"probe_errors", stats.ProbeErrors,
		"first_auth", stats.FirstAuth,
		"retries", stats.ProbeRetries,
	)

	if c.debugDataPublisher != nil {
		c.debugDataPublisher.PublishIfActive(livedebugging.NewData(
			livedebugging.ComponentID(c.opts.ID),
			livedebugging.Target,
			uint64(len(targets)),
			func() string { return fmt.Sprintf("%s", targets) },
		))
	}
	return nil
}

type tieredTarget struct {
	target snmpdiscovery.AlloyTarget
	tier   string
}

func expandTiers(catalog []snmpdiscovery.AlloyTarget, tier string) []tieredTarget {
	tier = strings.TrimSpace(strings.ToLower(tier))
	tiers := []string{"hot", "cold", "topology"}
	if tier != "" && tier != "all" {
		tiers = []string{tier}
	}
	var out []tieredTarget
	for _, t := range tiers {
		for _, at := range snmpdiscovery.TierTargets(catalog, t) {
			out = append(out, tieredTarget{target: at, tier: t})
		}
	}
	return out
}

func toDiscoveryTarget(t snmpdiscovery.AlloyTarget, tier string) discovery.Target {
	m := map[string]string{
		"name":        t.Name,
		"address":     t.Address,
		"module":      t.Module,
		"auth":        t.Auth,
		"device_name": t.DeviceName,
		"snmp_tier":   tier,
	}
	if t.SysObjectID != "" {
		m["sysObjectID"] = t.SysObjectID
	}
	if t.SnmpGroup != "" {
		m["snmp_group"] = t.SnmpGroup
	}
	if len(t.Aliases) > 0 {
		m["snmp_aliases"] = strings.Join(t.Aliases, ",")
	}
	return discovery.NewTargetFromMap(m)
}

func buildConfig(args Arguments) (snmpdiscovery.DiscoveryFile, error) {
	if path := strings.TrimSpace(args.ConfigPath); path != "" {
		cfg, err := snmpdiscovery.LoadDiscoveryFile(path)
		if err != nil {
			return cfg, err
		}
		if err := snmpdiscovery.MergeOverridesFile(&cfg, args.OverridesPath); err != nil {
			return cfg, err
		}
		cfg.Overrides = append(cfg.Overrides, convertOverrides(args.Overrides)...)
		return cfg, nil
	}

	cfg := snmpdiscovery.DiscoveryFile{
		Groups:    convertGroups(args),
		Overrides: convertOverrides(args.Overrides),
	}
	if err := snmpdiscovery.MergeOverridesFile(&cfg, args.OverridesPath); err != nil {
		return cfg, err
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func convertGroups(args Arguments) []snmpdiscovery.DiscoveryGroup {
	out := make([]snmpdiscovery.DiscoveryGroup, 0, len(args.Groups))
	for _, g := range args.Groups {
		fp := g.Fingerprinter
		if fp == "" {
			fp = args.Fingerprinter
		}
		port := uint16(g.Port)
		if port == 0 {
			port = uint16(args.Port)
		}
		out = append(out, snmpdiscovery.DiscoveryGroup{
			Name:          g.Name,
			CIDRs:         g.CIDRs,
			Exclude:       g.Exclude,
			Seeds:         g.Seeds,
			Auths:         g.Auths,
			Fingerprinter: fp,
			Port:          port,
			AllowLarge:    g.AllowLarge || args.AllowLarge,
			Mode:          g.Mode,
			Ping:          g.Ping,
		})
	}
	return out
}

func convertOverrides(in []OverrideArguments) []snmpdiscovery.Override {
	out := make([]snmpdiscovery.Override, 0, len(in))
	for _, o := range in {
		out = append(out, snmpdiscovery.Override{
			Address:        o.Address,
			Ignore:         o.Ignore,
			Name:           o.Name,
			Module:         o.Module,
			ModuleHot:      o.ModuleHot,
			ModuleCold:     o.ModuleCold,
			ModuleTopology: o.ModuleTopology,
			Auth:           o.Auth,
		})
	}
	return out
}
