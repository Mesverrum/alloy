package snmp

import (
	"github.com/Mesverrum/snmp-sd/snmpdiscovery"
	"github.com/grafana/alloy/internal/util"
	"github.com/prometheus/client_golang/prometheus"
)

// metrics for discovery.snmp.
type metrics struct {
	scans         prometheus.Counter
	failures      prometheus.Counter
	skipped       prometheus.Counter
	duration      prometheus.Histogram
	scanInFlight  prometheus.Gauge
	devices       prometheus.Gauge
	devicesGroup  *prometheus.GaugeVec
	targets       prometheus.Gauge
	targetsTier   *prometheus.GaugeVec
	sweep         prometheus.Gauge
	pingUp        prometheus.Gauge
	pingDead      prometheus.Gauge
	dropped       prometheus.Counter
	dedupes       prometheus.Gauge
	dedupesTot    prometheus.Counter
	stale         *prometheus.GaugeVec
	probes        *prometheus.CounterVec
	probeErrors   *prometheus.CounterVec
	probeDuration prometheus.Histogram
	inFlight      prometheus.Gauge
	probeOK       prometheus.Gauge
	probeErrs     prometheus.Gauge
	firstAuth     *prometheus.CounterVec
	authFallback  *prometheus.CounterVec
	authFailures  prometheus.Counter
	probeRetries  prometheus.Counter
	fingerprint   *prometheus.CounterVec
	modDropped    *prometheus.CounterVec
	deviceInfo    *prometheus.GaugeVec
	groupInfo     *prometheus.GaugeVec
	// One series per discovery.snmp instance: value is the profile count.
	libraryInfo *prometheus.GaugeVec
}

func newMetrics(reg prometheus.Registerer) *metrics {
	m := &metrics{
		scans: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "discovery_snmp_scans_total",
			Help: "Total number of SNMP discovery scans that ran to completion (success or failure).",
		}),
		failures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "discovery_snmp_scan_failures_total",
			Help: "Total number of SNMP discovery scans that failed.",
		}),
		skipped: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "discovery_snmp_scan_skipped_total",
			Help: "Total number of SNMP discovery ticks skipped because a previous scan was still running.",
		}),
		duration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "discovery_snmp_scan_duration_seconds",
			Help:    "Duration of completed SNMP discovery scans.",
			Buckets: []float64{1, 5, 15, 30, 60, 120, 300, 600},
		}),
		scanInFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "discovery_snmp_scan_in_progress",
			Help: "1 while an SNMP discovery scan is running.",
		}),
		devices: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "discovery_snmp_devices",
			Help: "Devices in the last successful SNMP discovery catalog.",
		}),
		devicesGroup: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "discovery_snmp_devices_by_group",
			Help: "Devices in the last successful catalog by discovery group.",
		}, []string{"group"}),
		targets: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "discovery_snmp_targets",
			Help: "Targets exported by the last successful SNMP discovery scan (after tier expansion).",
		}),
		targetsTier: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "discovery_snmp_targets_by_tier",
			Help: "Targets exported last scan by scrape tier.",
		}, []string{"tier"}),
		sweep: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "discovery_snmp_sweep_addresses",
			Help: "Addresses considered by the last successful CIDR sweep (before ICMP filter).",
		}),
		pingUp: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "discovery_snmp_ping_up",
			Help: "Addresses that passed the ICMP filter on the last successful scan.",
		}),
		pingDead: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "discovery_snmp_ping_dead",
			Help: "Addresses the ICMP filter dropped on the last successful scan (sweep minus ping_up).",
		}),
		dropped: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "discovery_snmp_dropped_total",
			Help: "Devices dropped from the catalog after consecutive silent discovery cycles.",
		}),
		dedupes: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "discovery_snmp_dedupes",
			Help: "SNMP addresses folded into another identity on the last successful scan (same sysName, lowest IP kept).",
		}),
		dedupesTot: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "discovery_snmp_dedupes_total",
			Help: "Total SNMP addresses folded into another identity because they shared a sysName.",
		}),
		stale: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "discovery_snmp_catalog_stale",
			Help: "Catalog entries with Misses > 0 after the last successful scan.",
		}, []string{"group"}),
		probes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "discovery_snmp_probes_total",
			Help: "SNMP identity probes (one per address).",
		}, []string{"result", "group"}),
		probeErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "discovery_snmp_probe_errors_total",
			Help: "SNMP identity probe failures by reason.",
		}, []string{"reason", "group"}),
		probeDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "discovery_snmp_probe_duration_seconds",
			Help:    "Duration of a single SNMP identity probe (all auths and retries).",
			Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10},
		}),
		inFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "discovery_snmp_probes_in_flight",
			Help: "SNMP identity probes currently running.",
		}),
		probeOK: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "discovery_snmp_probe_successes",
			Help: "Successful identity probes on the last successful scan.",
		}),
		probeErrs: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "discovery_snmp_probe_errors",
			Help: "Failed identity probes on the last successful scan.",
		}),
		firstAuth: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "discovery_snmp_first_auth_success_total",
			Help: "Probes that succeeded on the first named auth.",
		}, []string{"group"}),
		authFallback: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "discovery_snmp_auth_fallback_total",
			Help: "Probes that succeeded only after an earlier named auth failed.",
		}, []string{"group", "auth"}),
		authFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "discovery_snmp_auth_failures_total",
			Help: "Named-auth attempts that failed (connect, get, empty, or no sys*).",
		}),
		probeRetries: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "discovery_snmp_probe_retries_total",
			Help: "Extra SNMP Get attempts after the first try for an auth (configured retries).",
		}),
		fingerprint: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "discovery_snmp_fingerprint_total",
			Help: "Fingerprint outcome: known matcher vs default/unknown chain.",
		}, []string{"result", "group"}),
		modDropped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "discovery_snmp_modules_dropped_total",
			Help: "Fingerprinter module names missing from snmp.yml.",
		}, []string{"group"}),
		deviceInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "discovery_snmp_device_info",
			Help: "Last-good catalog identity (1 per device).",
		}, []string{"address", "device_name", "sysObjectID", "group", "auth"}),
		groupInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "discovery_snmp_group_info",
			Help: "Configured discovery groups and their operator description (1 per inline group block).",
		}, []string{"group", "description"}),
		libraryInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "discovery_snmp_library_info",
			Help: "Fingerprint library identity for this component. Value is the number of named profiles. One series per discovery.snmp instance.",
		}, []string{"fingerprinter", "library_hash"}),
	}
	if reg != nil {
		m.scans = util.MustRegisterOrGet(reg, m.scans).(prometheus.Counter)
		m.failures = util.MustRegisterOrGet(reg, m.failures).(prometheus.Counter)
		m.skipped = util.MustRegisterOrGet(reg, m.skipped).(prometheus.Counter)
		m.duration = util.MustRegisterOrGet(reg, m.duration).(prometheus.Histogram)
		m.scanInFlight = util.MustRegisterOrGet(reg, m.scanInFlight).(prometheus.Gauge)
		m.devices = util.MustRegisterOrGet(reg, m.devices).(prometheus.Gauge)
		m.devicesGroup = util.MustRegisterOrGet(reg, m.devicesGroup).(*prometheus.GaugeVec)
		m.targets = util.MustRegisterOrGet(reg, m.targets).(prometheus.Gauge)
		m.targetsTier = util.MustRegisterOrGet(reg, m.targetsTier).(*prometheus.GaugeVec)
		m.sweep = util.MustRegisterOrGet(reg, m.sweep).(prometheus.Gauge)
		m.pingUp = util.MustRegisterOrGet(reg, m.pingUp).(prometheus.Gauge)
		m.pingDead = util.MustRegisterOrGet(reg, m.pingDead).(prometheus.Gauge)
		m.dropped = util.MustRegisterOrGet(reg, m.dropped).(prometheus.Counter)
		m.dedupes = util.MustRegisterOrGet(reg, m.dedupes).(prometheus.Gauge)
		m.dedupesTot = util.MustRegisterOrGet(reg, m.dedupesTot).(prometheus.Counter)
		m.stale = util.MustRegisterOrGet(reg, m.stale).(*prometheus.GaugeVec)
		m.probes = util.MustRegisterOrGet(reg, m.probes).(*prometheus.CounterVec)
		m.probeErrors = util.MustRegisterOrGet(reg, m.probeErrors).(*prometheus.CounterVec)
		m.probeDuration = util.MustRegisterOrGet(reg, m.probeDuration).(prometheus.Histogram)
		m.inFlight = util.MustRegisterOrGet(reg, m.inFlight).(prometheus.Gauge)
		m.probeOK = util.MustRegisterOrGet(reg, m.probeOK).(prometheus.Gauge)
		m.probeErrs = util.MustRegisterOrGet(reg, m.probeErrs).(prometheus.Gauge)
		m.firstAuth = util.MustRegisterOrGet(reg, m.firstAuth).(*prometheus.CounterVec)
		m.authFallback = util.MustRegisterOrGet(reg, m.authFallback).(*prometheus.CounterVec)
		m.authFailures = util.MustRegisterOrGet(reg, m.authFailures).(prometheus.Counter)
		m.probeRetries = util.MustRegisterOrGet(reg, m.probeRetries).(prometheus.Counter)
		m.fingerprint = util.MustRegisterOrGet(reg, m.fingerprint).(*prometheus.CounterVec)
		m.modDropped = util.MustRegisterOrGet(reg, m.modDropped).(*prometheus.CounterVec)
		m.deviceInfo = util.MustRegisterOrGet(reg, m.deviceInfo).(*prometheus.GaugeVec)
		m.groupInfo = util.MustRegisterOrGet(reg, m.groupInfo).(*prometheus.GaugeVec)
		m.libraryInfo = util.MustRegisterOrGet(reg, m.libraryInfo).(*prometheus.GaugeVec)
	}
	for _, r := range []string{"success", "error"} {
		m.probes.WithLabelValues(r, "unknown")
	}
	for _, r := range []string{
		snmpdiscovery.ProbeReasonTimeout,
		snmpdiscovery.ProbeReasonRefused,
		snmpdiscovery.ProbeReasonConnect,
		snmpdiscovery.ProbeReasonEmpty,
		snmpdiscovery.ProbeReasonNoSys,
		snmpdiscovery.ProbeReasonNoAuth,
		snmpdiscovery.ProbeReasonOther,
	} {
		m.probeErrors.WithLabelValues(r, "unknown")
	}
	m.fingerprint.WithLabelValues(snmpdiscovery.FingerprintKnown, "unknown")
	m.fingerprint.WithLabelValues(snmpdiscovery.FingerprintUnknown, "unknown")
	return m
}

var _ snmpdiscovery.DeviceObserver = probeHook{}

type probeHook struct {
	m *metrics
}

func (h probeHook) ProbeBegin() {
	if h.m == nil {
		return
	}
	h.m.inFlight.Inc()
}

func (h probeHook) ProbeEnd(d snmpdiscovery.ProbeDetail) {
	if h.m == nil {
		return
	}
	h.m.inFlight.Dec()
	h.m.probeDuration.Observe(d.Duration.Seconds())
	group := metricGroup(d.Group)
	if d.Success {
		h.m.probes.WithLabelValues("success", group).Inc()
		if d.FirstAuth {
			h.m.firstAuth.WithLabelValues(group).Inc()
		} else {
			h.m.authFallback.WithLabelValues(group, metricGroup(d.Auth)).Inc()
		}
	} else {
		h.m.probes.WithLabelValues("error", group).Inc()
		reason := d.Reason
		if reason == "" || reason == snmpdiscovery.ProbeReasonOK {
			reason = snmpdiscovery.ProbeReasonOther
		}
		h.m.probeErrors.WithLabelValues(reason, group).Inc()
	}
	if d.AuthFails > 0 {
		h.m.authFailures.Add(float64(d.AuthFails))
	}
	if d.Retries > 0 {
		h.m.probeRetries.Add(float64(d.Retries))
	}
}

func (h probeHook) DeviceFound(d snmpdiscovery.DeviceFoundDetail) {
	if h.m == nil {
		return
	}
	group := metricGroup(d.Group)
	result := d.Fingerprint
	if result == "" {
		result = snmpdiscovery.FingerprintUnknown
	}
	h.m.fingerprint.WithLabelValues(result, group).Inc()
	if n := len(d.DroppedModules); n > 0 {
		h.m.modDropped.WithLabelValues(group).Add(float64(n))
	}
}

func (m *metrics) observeCatalog(published []snmpdiscovery.AlloyTarget, cat *snmpdiscovery.Catalog, tiers []string, exported int) {
	if m == nil {
		return
	}
	m.devices.Set(float64(len(published)))
	m.targets.Set(float64(exported))
	m.devicesGroup.Reset()
	m.stale.Reset()
	m.deviceInfo.Reset()
	m.targetsTier.Reset()
	byGroup := map[string]int{}
	if cat != nil {
		for _, e := range cat.SnapshotEntries() {
			g := metricGroup(e.Target.SnmpGroup)
			byGroup[g]++
			if e.Misses > 0 {
				m.stale.WithLabelValues(g).Inc()
			}
			m.deviceInfo.WithLabelValues(
				e.Target.Address,
				e.Target.DeviceName,
				e.Target.SysObjectID,
				g,
				metricGroup(e.Target.Auth),
			).Set(1)
		}
	} else {
		for _, t := range published {
			byGroup[metricGroup(t.SnmpGroup)]++
		}
	}
	for g, n := range byGroup {
		m.devicesGroup.WithLabelValues(g).Set(float64(n))
	}
	for _, tier := range tiers {
		m.targetsTier.WithLabelValues(tier).Set(float64(len(snmpdiscovery.TierTargets(published, tier))))
	}
}

// observeGroups publishes the configured inline groups. It runs on every
// successful config apply (not per scan) so the description is visible
// before the first scan finishes and follows edits immediately. Groups
// loaded from config_path are not listed here; only inline blocks carry a
// description.
func (m *metrics) observeGroups(groups []GroupArguments) {
	if m == nil {
		return
	}
	out := make([]snmpdiscovery.DiscoveryGroup, 0, len(groups))
	for _, g := range groups {
		out = append(out, snmpdiscovery.DiscoveryGroup{Name: g.Name, Description: g.Description})
	}
	m.observeDiscoveryGroups(out)
}

// observeDiscoveryGroups publishes the groups the scan will actually use,
// including groups loaded from config_path. Updated on config apply for
// inline groups, and again after each successful scan.
func (m *metrics) observeDiscoveryGroups(groups []snmpdiscovery.DiscoveryGroup) {
	if m == nil {
		return
	}
	m.groupInfo.Reset()
	for _, g := range groups {
		m.groupInfo.WithLabelValues(metricGroup(g.Name), g.Description).Set(1)
	}
}

func metricGroup(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// observeLibrary publishes one series for the loaded fingerprinter catalog.
// library_hash changes when the file changes; custom customer catalogs are first-class.
func (m *metrics) observeLibrary(lib FingerprintLibrary) {
	if m == nil {
		return
	}
	m.libraryInfo.Reset()
	if lib.LibraryHash == "" {
		return
	}
	fp := metricGroup(lib.Fingerprinter)
	m.libraryInfo.WithLabelValues(fp, lib.LibraryHash).Set(float64(len(lib.Profiles)))
}
