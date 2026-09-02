package syslogtarget

// This code is copied from Promtail. The syslogtarget package is used to
// configure and run the targets that can read syslog entries and forward them
// to other loki components.

import (
	"github.com/grafana/alloy/internal/util"
	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds a set of syslog metrics.
type Metrics struct {
	reg prometheus.Registerer

	syslogEntries       prometheus.Counter
	syslogParsingErrors prometheus.Counter
	syslogEmptyMessages prometheus.Counter
	joined              prometheus.Counter
	unjoined            prometheus.Counter
}

// NewMetrics creates a new set of syslog metrics. If reg is non-nil, the
// metrics will be registered.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	var m Metrics
	m.reg = reg

	m.syslogEntries = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "loki_source_syslog_entries_total",
		Help: "Total number of successful entries sent to the syslog target",
	})
	m.syslogParsingErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "loki_source_syslog_parsing_errors_total",
		Help: "Total number of parsing errors while receiving syslog messages",
	})
	m.syslogEmptyMessages = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "loki_source_syslog_empty_messages_total",
		Help: "Total number of empty messages received from syslog",
	})
	m.joined = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "loki_source_syslog_joined_total",
		Help: "Syslog messages whose source IP or hostname matched a discovery identity (device_name).",
	})
	m.unjoined = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "loki_source_syslog_unjoined_total",
		Help: "Syslog messages received while a discovery catalog was set but the source was unknown.",
	})

	if reg != nil {
		m.syslogEntries = util.MustRegisterOrGet(reg, m.syslogEntries).(prometheus.Counter)
		m.syslogParsingErrors = util.MustRegisterOrGet(reg, m.syslogParsingErrors).(prometheus.Counter)
		m.syslogEmptyMessages = util.MustRegisterOrGet(reg, m.syslogEmptyMessages).(prometheus.Counter)
		m.joined = util.MustRegisterOrGet(reg, m.joined).(prometheus.Counter)
		m.unjoined = util.MustRegisterOrGet(reg, m.unjoined).(prometheus.Counter)
	}

	return &m
}

// Joined is the catalog-hit counter (nil-safe).
func (m *Metrics) Joined() prometheus.Counter {
	if m == nil {
		return nil
	}
	return m.joined
}

// Unjoined is the catalog-miss counter (nil-safe).
func (m *Metrics) Unjoined() prometheus.Counter {
	if m == nil {
		return nil
	}
	return m.unjoined
}
