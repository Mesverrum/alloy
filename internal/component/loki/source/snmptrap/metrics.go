package snmptrap

import (
	"fmt"

	"github.com/gosnmp/gosnmp"
	"github.com/grafana/alloy/internal/util"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	reasonQueueFull = "queue_full"
	reasonUndefined = "undefined"
	reasonCommunity = "community"
	trapQueueCap    = 1024
)

// Metrics for loki.source.snmptrap.
type Metrics struct {
	received       *prometheus.CounterVec
	entries        prometheus.Counter
	errors         prometheus.Counter
	joined         prometheus.Counter
	unjoined       prometheus.Counter
	dropped        *prometheus.CounterVec
	queueLen       prometheus.Gauge
	queueCap       prometheus.Gauge
	handleDuration prometheus.Histogram
}

func newMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		received: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "loki_source_snmptrap_received_total",
			Help: "SNMP trap/inform packets accepted by the UDP listener.",
		}, []string{"pdu"}),
		entries: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "loki_source_snmptrap_entries_total",
			Help: "Total number of SNMP trap/inform entries forwarded",
		}),
		errors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "loki_source_snmptrap_errors_total",
			Help: "Total number of SNMP trap decode or marshal errors",
		}),
		joined: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "loki_source_snmptrap_joined_total",
			Help: "Traps whose source IP matched a discovery identity (device_name).",
		}),
		unjoined: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "loki_source_snmptrap_unjoined_total",
			Help: "Traps received while a discovery catalog was set but the source IP was unknown.",
		}),
		dropped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "loki_source_snmptrap_dropped_total",
			Help: "Total number of SNMP traps dropped before forwarding",
		}, []string{"reason"}),
		queueLen: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "loki_source_snmptrap_queue_length",
			Help: "Log entries waiting to be forwarded (outbound channel depth).",
		}),
		queueCap: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "loki_source_snmptrap_queue_capacity",
			Help: "Outbound channel capacity. queue_length / queue_capacity is backlog.",
		}),
		handleDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "loki_source_snmptrap_handle_duration_seconds",
			Help:    "Time to decode and enqueue one trap/inform.",
			Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1},
		}),
	}
	if reg != nil {
		m.received = util.MustRegisterOrGet(reg, m.received).(*prometheus.CounterVec)
		m.entries = util.MustRegisterOrGet(reg, m.entries).(prometheus.Counter)
		m.errors = util.MustRegisterOrGet(reg, m.errors).(prometheus.Counter)
		m.joined = util.MustRegisterOrGet(reg, m.joined).(prometheus.Counter)
		m.unjoined = util.MustRegisterOrGet(reg, m.unjoined).(prometheus.Counter)
		m.dropped = util.MustRegisterOrGet(reg, m.dropped).(*prometheus.CounterVec)
		m.queueLen = util.MustRegisterOrGet(reg, m.queueLen).(prometheus.Gauge)
		m.queueCap = util.MustRegisterOrGet(reg, m.queueCap).(prometheus.Gauge)
		m.handleDuration = util.MustRegisterOrGet(reg, m.handleDuration).(prometheus.Histogram)
	}
	for _, r := range []string{reasonQueueFull, reasonUndefined, reasonCommunity} {
		m.dropped.WithLabelValues(r)
	}
	m.received.WithLabelValues("trap")
	m.received.WithLabelValues("inform")
	m.queueCap.Set(trapQueueCap)
	return m
}

func (m *Metrics) drop(reason string) {
	if m == nil || m.dropped == nil {
		return
	}
	m.dropped.WithLabelValues(reason).Inc()
}

func (m *Metrics) noteQueue(n int) {
	if m == nil || m.queueLen == nil {
		return
	}
	m.queueLen.Set(float64(n))
}

func trapPDULabel(t gosnmp.PDUType) string {
	if t == gosnmp.InformRequest {
		return "inform"
	}
	return "trap"
}

func unknownEnum(kind, v string) error {
	return fmt.Errorf("unknown %s %q", kind, v)
}
