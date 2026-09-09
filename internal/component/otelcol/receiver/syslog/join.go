package syslog

import (
	"context"
	"reflect"
	"sync"
	"sync/atomic"

	"github.com/grafana/alloy/internal/component"
	"github.com/grafana/alloy/internal/component/common/devicejoin"
	"github.com/grafana/alloy/internal/component/otelcol"
	"github.com/grafana/alloy/internal/component/otelcol/receiver"
	"github.com/grafana/alloy/internal/util"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/syslogreceiver"
	"github.com/prometheus/client_golang/prometheus"
	otelconsumer "go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

// peerAddrKeys are the source-IP attributes stanza add_attributes (and
// newer semconv) may set on a syslog record or its resource.
var peerAddrKeys = []string{
	"net.peer.ip",
	"net.sock.peer.addr",
	"network.peer.address",
	"net.peer.addr",
}

// Component wraps the contrib syslog receiver so an optional discovery
// catalog can stamp device_name without restarting the listener.
type Component struct {
	inner   *receiver.Receiver
	join    atomic.Pointer[devicejoin.Index]
	metrics *joinMetrics

	mut        sync.Mutex
	lastListen Arguments
}

var (
	_ component.Component       = (*Component)(nil)
	_ component.HealthComponent = (*Component)(nil)
	_ component.LiveDebugging   = (*Component)(nil)
	_ receiver.Arguments        = joiningArgs{}
	_ otelcol.Consumer          = (*joinConsumer)(nil)
)

type joinMetrics struct {
	joined   prometheus.Counter
	unjoined prometheus.Counter
}

func newJoinMetrics(reg prometheus.Registerer) *joinMetrics {
	m := &joinMetrics{
		joined: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "otelcol_receiver_syslog_joined_total",
			Help: "Syslog messages whose source IP or hostname matched a discovery identity (device_name).",
		}),
		unjoined: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "otelcol_receiver_syslog_unjoined_total",
			Help: "Syslog messages received while a discovery catalog was set but the source was unknown.",
		}),
	}
	if reg != nil {
		m.joined = util.MustRegisterOrGet(reg, m.joined).(prometheus.Counter)
		m.unjoined = util.MustRegisterOrGet(reg, m.unjoined).(prometheus.Counter)
	}
	return m
}

// New builds otelcol.receiver.syslog with optional devicejoin on log records.
func New(opts component.Options, args Arguments) (*Component, error) {
	c := &Component{
		metrics: newJoinMetrics(opts.Registerer),
	}
	c.join.Store(devicejoin.NewIndex(args.Targets))
	inner, err := receiver.New(opts, syslogreceiver.NewFactory(), joiningArgs{comp: c, Arguments: args})
	if err != nil {
		return nil, err
	}
	c.inner = inner
	c.lastListen = args
	return c, nil
}

// Run implements component.Component.
func (c *Component) Run(ctx context.Context) error {
	return c.inner.Run(ctx)
}

// Update implements component.Component. Catalog-only changes refresh the
// join index without recreating the UDP/TCP receiver.
func (c *Component) Update(args component.Arguments) error {
	a := args.(Arguments)
	c.join.Store(devicejoin.NewIndex(a.Targets))

	c.mut.Lock()
	defer c.mut.Unlock()
	if listenConfigEqual(c.lastListen, a) {
		return nil
	}
	c.lastListen = a
	return c.inner.Update(joiningArgs{comp: c, Arguments: a})
}

// CurrentHealth implements component.HealthComponent.
func (c *Component) CurrentHealth() component.Health {
	return c.inner.CurrentHealth()
}

// LiveDebugging implements component.LiveDebugging.
func (*Component) LiveDebugging() {}

func listenConfigEqual(a, b Arguments) bool {
	a.Targets = nil
	b.Targets = nil
	return reflect.DeepEqual(a, b)
}

// joiningArgs embeds syslog Arguments and wraps log consumers with devicejoin.
type joiningArgs struct {
	comp *Component
	Arguments
}

func (a joiningArgs) NextConsumers() *otelcol.ConsumerArguments {
	next := a.Arguments.NextConsumers()
	if next == nil || a.comp == nil {
		return next
	}
	logs := make([]otelcol.Consumer, 0, len(next.Logs))
	for _, cons := range next.Logs {
		logs = append(logs, &joinConsumer{
			next:    cons,
			join:    &a.comp.join,
			metrics: a.comp.metrics,
		})
	}
	out := *next
	out.Logs = logs
	return &out
}

type joinConsumer struct {
	next    otelcol.Consumer
	join    *atomic.Pointer[devicejoin.Index]
	metrics *joinMetrics
}

func (c *joinConsumer) Capabilities() otelconsumer.Capabilities {
	return otelconsumer.Capabilities{MutatesData: true}
}

func (c *joinConsumer) ConsumeTraces(ctx context.Context, td ptrace.Traces) error {
	if c.next == nil {
		return nil
	}
	return c.next.ConsumeTraces(ctx, td)
}

func (c *joinConsumer) ConsumeMetrics(ctx context.Context, md pmetric.Metrics) error {
	if c.next == nil {
		return nil
	}
	return c.next.ConsumeMetrics(ctx, md)
}

func (c *joinConsumer) ConsumeLogs(ctx context.Context, ld plog.Logs) error {
	var idx *devicejoin.Index
	if c.join != nil {
		idx = c.join.Load()
	}
	stampSyslogJoin(ld, idx, c.metrics)
	if c.next == nil {
		return nil
	}
	return c.next.ConsumeLogs(ctx, ld)
}

func stampSyslogJoin(ld plog.Logs, idx *devicejoin.Index, m *joinMetrics) {
	if idx.Len() == 0 {
		return
	}
	rls := ld.ResourceLogs()
	for i := 0; i < rls.Len(); i++ {
		rl := rls.At(i)
		res := rl.Resource().Attributes()
		sls := rl.ScopeLogs()
		for j := 0; j < sls.Len(); j++ {
			recs := sls.At(j).LogRecords()
			for k := 0; k < recs.Len(); k++ {
				stampSyslogRecord(recs.At(k), res, idx, m)
			}
		}
	}
}

func stampSyslogRecord(rec plog.LogRecord, res pcommon.Map, idx *devicejoin.Index, m *joinMetrics) {
	attrs := rec.Attributes()
	ip := firstAttr(attrs, res, peerAddrKeys...)
	host := firstAttr(attrs, res, "hostname")
	id, ok := idx.Lookup(ip, host)
	if !ok {
		if m != nil && m.unjoined != nil {
			m.unjoined.Inc()
		}
		return
	}
	if id.DeviceName != "" {
		attrs.PutStr("device_name", id.DeviceName)
	}
	if id.Group != "" {
		attrs.PutStr("snmp_group", id.Group)
	}
	if m != nil && m.joined != nil {
		m.joined.Inc()
	}
}

func firstAttr(attrs, res pcommon.Map, keys ...string) string {
	for _, key := range keys {
		if v := attrStr(attrs, key); v != "" {
			return v
		}
		if v := attrStr(res, key); v != "" {
			return v
		}
	}
	return ""
}

func attrStr(attrs pcommon.Map, key string) string {
	v, ok := attrs.Get(key)
	if !ok {
		return ""
	}
	return v.AsString()
}
