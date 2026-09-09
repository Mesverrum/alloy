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
	targets       prometheus.Gauge
	sweep         prometheus.Gauge
	pingUp        prometheus.Gauge
	pingDead      prometheus.Gauge
	dropped       prometheus.Counter
	dedupes       prometheus.Gauge
	dedupesTot    prometheus.Counter
	probes        *prometheus.CounterVec
	probeErrors   *prometheus.CounterVec
	probeDuration prometheus.Histogram
	inFlight      prometheus.Gauge
	probeOK       prometheus.Gauge
	probeErrs     prometheus.Gauge
	firstAuth     prometheus.Counter
	authFallback  prometheus.Counter
	authFailures  prometheus.Counter
	probeRetries  prometheus.Counter
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
		targets: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "discovery_snmp_targets",
			Help: "Targets exported by the last successful SNMP discovery scan (after tier expansion).",
		}),
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
		probes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "discovery_snmp_probes_total",
			Help: "SNMP identity probes (one per address).",
		}, []string{"result"}),
		probeErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "discovery_snmp_probe_errors_total",
			Help: "SNMP identity probe failures by reason.",
		}, []string{"reason"}),
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
		firstAuth: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "discovery_snmp_first_auth_success_total",
			Help: "Probes that succeeded on the first named auth.",
		}),
		authFallback: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "discovery_snmp_auth_fallback_total",
			Help: "Probes that succeeded only after an earlier named auth failed.",
		}),
		authFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "discovery_snmp_auth_failures_total",
			Help: "Named-auth attempts that failed (connect, get, empty, or no sys*).",
		}),
		probeRetries: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "discovery_snmp_probe_retries_total",
			Help: "Extra SNMP Get attempts after the first try for an auth (configured retries).",
		}),
	}
	if reg != nil {
		m.scans = util.MustRegisterOrGet(reg, m.scans).(prometheus.Counter)
		m.failures = util.MustRegisterOrGet(reg, m.failures).(prometheus.Counter)
		m.skipped = util.MustRegisterOrGet(reg, m.skipped).(prometheus.Counter)
		m.duration = util.MustRegisterOrGet(reg, m.duration).(prometheus.Histogram)
		m.scanInFlight = util.MustRegisterOrGet(reg, m.scanInFlight).(prometheus.Gauge)
		m.devices = util.MustRegisterOrGet(reg, m.devices).(prometheus.Gauge)
		m.targets = util.MustRegisterOrGet(reg, m.targets).(prometheus.Gauge)
		m.sweep = util.MustRegisterOrGet(reg, m.sweep).(prometheus.Gauge)
		m.pingUp = util.MustRegisterOrGet(reg, m.pingUp).(prometheus.Gauge)
		m.pingDead = util.MustRegisterOrGet(reg, m.pingDead).(prometheus.Gauge)
		m.dropped = util.MustRegisterOrGet(reg, m.dropped).(prometheus.Counter)
		m.dedupes = util.MustRegisterOrGet(reg, m.dedupes).(prometheus.Gauge)
		m.dedupesTot = util.MustRegisterOrGet(reg, m.dedupesTot).(prometheus.Counter)
		m.probes = util.MustRegisterOrGet(reg, m.probes).(*prometheus.CounterVec)
		m.probeErrors = util.MustRegisterOrGet(reg, m.probeErrors).(*prometheus.CounterVec)
		m.probeDuration = util.MustRegisterOrGet(reg, m.probeDuration).(prometheus.Histogram)
		m.inFlight = util.MustRegisterOrGet(reg, m.inFlight).(prometheus.Gauge)
		m.probeOK = util.MustRegisterOrGet(reg, m.probeOK).(prometheus.Gauge)
		m.probeErrs = util.MustRegisterOrGet(reg, m.probeErrs).(prometheus.Gauge)
		m.firstAuth = util.MustRegisterOrGet(reg, m.firstAuth).(prometheus.Counter)
		m.authFallback = util.MustRegisterOrGet(reg, m.authFallback).(prometheus.Counter)
		m.authFailures = util.MustRegisterOrGet(reg, m.authFailures).(prometheus.Counter)
		m.probeRetries = util.MustRegisterOrGet(reg, m.probeRetries).(prometheus.Counter)
	}
	m.probes.WithLabelValues("success")
	m.probes.WithLabelValues("error")
	for _, r := range []string{
		snmpdiscovery.ProbeReasonTimeout,
		snmpdiscovery.ProbeReasonRefused,
		snmpdiscovery.ProbeReasonConnect,
		snmpdiscovery.ProbeReasonEmpty,
		snmpdiscovery.ProbeReasonNoSys,
		snmpdiscovery.ProbeReasonNoAuth,
		snmpdiscovery.ProbeReasonOther,
	} {
		m.probeErrors.WithLabelValues(r)
	}
	return m
}

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
	if d.Success {
		h.m.probes.WithLabelValues("success").Inc()
		if d.FirstAuth {
			h.m.firstAuth.Inc()
		} else {
			h.m.authFallback.Inc()
		}
	} else {
		h.m.probes.WithLabelValues("error").Inc()
		reason := d.Reason
		if reason == "" || reason == snmpdiscovery.ProbeReasonOK {
			reason = snmpdiscovery.ProbeReasonOther
		}
		h.m.probeErrors.WithLabelValues(reason).Inc()
	}
	if d.AuthFails > 0 {
		h.m.authFailures.Add(float64(d.AuthFails))
	}
	if d.Retries > 0 {
		h.m.probeRetries.Add(float64(d.Retries))
	}
}
