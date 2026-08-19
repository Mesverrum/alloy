package netflow

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
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/netflowreceiver"
	"github.com/prometheus/client_golang/prometheus"
	otelconsumer "go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

const (
	attrSampler = "flow.sampler_address"
	attrSource  = "source.address"
	attrDest    = "destination.address"
)

// Component wraps the contrib netflow receiver so an optional discovery
// catalog can stamp device_name without restarting the UDP listener.
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
			Name: "otelcol_receiver_netflow_joined_total",
			Help: "Flow records whose flow.sampler_address matched a discovery identity (device_name).",
		}),
		unjoined: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "otelcol_receiver_netflow_unjoined_total",
			Help: "Flow records received while a discovery catalog was set but the sampler was unknown.",
		}),
	}
	if reg != nil {
		m.joined = util.MustRegisterOrGet(reg, m.joined).(prometheus.Counter)
		m.unjoined = util.MustRegisterOrGet(reg, m.unjoined).(prometheus.Counter)
	}
	return m
}

// New builds otelcol.receiver.netflow with optional devicejoin on log records.
func New(opts component.Options, args Arguments) (*Component, error) {
	c := &Component{
		metrics: newJoinMetrics(opts.Registerer),
	}
	c.join.Store(devicejoin.NewIndex(args.Targets))
	inner, err := receiver.New(opts, netflowreceiver.NewFactory(), joiningArgs{comp: c, Arguments: args})
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
// join index without recreating the UDP receiver.
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

// joiningArgs embeds netflow Arguments and wraps log consumers with devicejoin.
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
		logs = append(logs, &joinConsumer{next: cons, join: &a.comp.join, metrics: a.comp.metrics})
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
	stampFlowJoin(ld, idx, c.metrics)
	if c.next == nil {
		return nil
	}
	return c.next.ConsumeLogs(ctx, ld)
}

func stampFlowJoin(ld plog.Logs, idx *devicejoin.Index, m *joinMetrics) {
	if idx.Len() == 0 {
		return
	}
	rls := ld.ResourceLogs()
	for i := 0; i < rls.Len(); i++ {
		sls := rls.At(i).ScopeLogs()
		for j := 0; j < sls.Len(); j++ {
			recs := sls.At(j).LogRecords()
			for k := 0; k < recs.Len(); k++ {
				stampFlowRecord(recs.At(k).Attributes(), idx, m)
			}
		}
	}
}

func stampFlowRecord(attrs pcommon.Map, idx *devicejoin.Index, m *joinMetrics) {
	sampler := attrStr(attrs, attrSampler)
	src := attrStr(attrs, attrSource)
	dst := attrStr(attrs, attrDest)

	if id, ok := idx.Lookup(sampler); ok {
		if id.DeviceName != "" {
			attrs.PutStr("device_name", id.DeviceName)
		}
		if id.Group != "" {
			attrs.PutStr("snmp_group", id.Group)
		}
		if m != nil && m.joined != nil {
			m.joined.Inc()
		}
	} else if sampler != "" {
		if m != nil && m.unjoined != nil {
			m.unjoined.Inc()
		}
	}
	if id, ok := idx.Lookup(src); ok && id.DeviceName != "" {
		attrs.PutStr("src_device", id.DeviceName)
	}
	if id, ok := idx.Lookup(dst); ok && id.DeviceName != "" {
		attrs.PutStr("dst_device", id.DeviceName)
	}
}

func attrStr(attrs pcommon.Map, key string) string {
	v, ok := attrs.Get(key)
	if !ok {
		return ""
	}
	return v.AsString()
}
