package snmptrap

import (
	"github.com/grafana/alloy/internal/util"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	reasonQueueFull = "queue_full"
	reasonUndefined = "undefined"
	reasonCommunity = "community"
	trapQueueCap    = 1024
)

type recvMetrics struct {
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

func newRecvMetrics(reg prometheus.Registerer) *recvMetrics {
	m := &recvMetrics{
		received: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "otelcol_receiver_snmptrap_received_total",
			Help: "SNMP trap/inform packets accepted by the UDP listener.",
		}, []string{"pdu"}),
		entries: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "otelcol_receiver_snmptrap_entries_total",
			Help: "SNMP trap/inform logs forwarded to the OTel pipeline.",
		}),
		errors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "otelcol_receiver_snmptrap_errors_total",
			Help: "SNMP trap decode or marshal errors.",
		}),
		joined: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "otelcol_receiver_snmptrap_joined_total",
			Help: "Traps whose source IP matched a discovery identity (device_name).",
		}),
		unjoined: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "otelcol_receiver_snmptrap_unjoined_total",
			Help: "Traps received while a discovery catalog was set but the source IP was unknown.",
		}),
		dropped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "otelcol_receiver_snmptrap_dropped_total",
			Help: "SNMP traps dropped before forwarding.",
		}, []string{"reason"}),
		queueLen: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "otelcol_receiver_snmptrap_queue_length",
			Help: "OTel log batches waiting to be forwarded.",
		}),
		queueCap: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "otelcol_receiver_snmptrap_queue_capacity",
			Help: "Outbound channel capacity. queue_length / queue_capacity is backlog.",
		}),
		handleDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "otelcol_receiver_snmptrap_handle_duration_seconds",
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

func (m *recvMetrics) drop(reason string) {
	if m == nil || m.dropped == nil {
		return
	}
	m.dropped.WithLabelValues(reason).Inc()
}

func (m *recvMetrics) noteQueue(n int) {
	if m == nil || m.queueLen == nil {
		return
	}
	m.queueLen.Set(float64(n))
}
