package topology

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/prometheus/model/exemplar"
	"github.com/prometheus/prometheus/model/histogram"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/metadata"
	"github.com/prometheus/prometheus/model/value"
	"github.com/prometheus/prometheus/storage"

	"github.com/grafana/alloy/internal/component"
	promcfg "github.com/grafana/alloy/internal/component/prometheus"
	"github.com/grafana/alloy/internal/featuregate"
	"github.com/grafana/alloy/internal/service/labelstore"
)

func init() {
	component.Register(component.Registration{
		Name:      "prometheus.network_topology",
		Stability: featuregate.StabilityExperimental,
		Args:      Arguments{},
		Exports:   Exports{},
		Build: func(opts component.Options, args component.Arguments) (component.Component, error) {
			return New(opts, args.(Arguments))
		},
	})
}

// Arguments configures prometheus.network_topology. Wire neighbor samples here:
// the SNMP topology-tier scrape, or gnmic series whose names contain
// lldp_interface_neighbor. A sample is kept only when its name contains
// lldp_interface_neighbor, lldpremsysname, lldpremportid, lldplocport,
// cdpcachedeviceid, cdpcachedeviceport, tbgppeerngconnstate, or bgppeerstate.
// Every other series is discarded and is not written to forward_to.
// forward_to receives network_topology_device_info and network_topology_edge_info.
type Arguments struct {
	ForwardTo  []storage.Appendable `alloy:"forward_to,attr"`
	StaleAfter time.Duration        `alloy:"stale_after,attr,optional"`
}

func (a *Arguments) SetToDefault() {
	*a = Arguments{StaleAfter: 30 * time.Minute}
}

func (a *Arguments) Validate() error {
	if a.StaleAfter <= 0 {
		return fmt.Errorf("stale_after must be > 0")
	}
	return nil
}

type Exports struct {
	Receiver storage.Appendable `alloy:"receiver,attr"`
}

type seriesPoint struct {
	labels labels.Labels
	t      int64
	v      float64
}

// Component reconciles a topology-tier scrape into a graph and appends that
// graph to forward_to. The last graph is kept across Update. A scrape that
// carries no neighbor samples does not replace it.
type Component struct {
	opts     component.Options
	receiver *receive

	mut           sync.Mutex
	staleAfter    time.Duration
	fanout        *promcfg.Fanout
	samples       map[string]sample
	edges         []edge
	samplesGauge  prometheus.Gauge
	edgesGauge    prometheus.Gauge
	unmatched     prometheus.Gauge
	unresolved    prometheus.Gauge
	lastReconcile prometheus.Gauge
	lastGraph     prometheus.Gauge
	ignored       prometheus.Counter
	staleDropped  prometheus.Counter
	byEvidence    *prometheus.GaugeVec
}

func New(o component.Options, args Arguments) (*Component, error) {
	data, err := o.GetServiceData(labelstore.ServiceName)
	if err != nil {
		return nil, err
	}
	c := &Component{
		opts:    o,
		samples: map[string]sample{},
	}
	c.samplesGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "alloy_prometheus_network_topology_samples",
		Help: "Neighbor samples held for reconciliation, including local-port helpers. Aged out after stale_after.",
	})
	c.edgesGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "alloy_prometheus_network_topology_edges",
		Help: "Edges from the last commit that contained neighbor samples. A commit with none keeps this value.",
	})
	c.unmatched = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "alloy_prometheus_network_topology_unmatched_samples",
		Help: "Samples in the last reconcile that were not local-port helpers and matched no family.",
	})
	c.unresolved = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "alloy_prometheus_network_topology_unresolved_sessions",
		Help: "Established sessions in the last reconcile whose peer address no reporter claims as its own; dst_device stays the address.",
	})
	c.lastReconcile = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "alloy_prometheus_network_topology_last_reconcile_timestamp_seconds",
		Help: "Unix time of the last commit that contained neighbor samples.",
	})
	c.lastGraph = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "alloy_prometheus_network_topology_last_graph_timestamp_seconds",
		Help: "Unix time of the last reconcile that produced at least one edge.",
	})
	c.ignored = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "alloy_prometheus_network_topology_ignored_commits_total",
		Help: "Commits that contained no neighbor samples. The previous graph is kept.",
	})
	c.staleDropped = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "alloy_prometheus_network_topology_stale_samples_total",
		Help: "Samples dropped because they were older than stale_after.",
	})
	c.byEvidence = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "alloy_prometheus_network_topology_edges_by_evidence",
		Help: "Edges from the last reconcile, by evidence. Series exist only for evidences present in that reconcile.",
	}, []string{"evidence"})
	for _, col := range []prometheus.Collector{
		c.samplesGauge, c.edgesGauge, c.unmatched, c.unresolved, c.lastReconcile, c.lastGraph,
		c.ignored, c.staleDropped, c.byEvidence,
	} {
		if err := o.Registerer.Register(col); err != nil {
			return nil, err
		}
	}
	c.fanout = promcfg.NewFanout(args.ForwardTo, o.ID, o.Registerer, data.(labelstore.LabelStore))
	c.receiver = &receive{comp: c}
	o.OnStateChange(Exports{Receiver: c.receiver})
	if err := c.Update(args); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Component) Run(ctx context.Context) error {
	defer c.fanout.Clear()
	<-ctx.Done()
	return nil
}

func (c *Component) Update(args component.Arguments) error {
	a := args.(Arguments)
	data, err := c.opts.GetServiceData(labelstore.ServiceName)
	if err != nil {
		return err
	}
	c.mut.Lock()
	defer c.mut.Unlock()
	c.staleAfter = a.StaleAfter
	c.fanout = promcfg.NewFanout(a.ForwardTo, c.opts.ID, c.opts.Registerer, data.(labelstore.LabelStore))
	return nil
}

func (c *Component) ingest(batch []sample, now time.Time) (touched bool, points []seriesPoint) {
	c.mut.Lock()
	defer c.mut.Unlock()
	received := 0
	for _, s := range batch {
		if !relevant(s.Name) {
			continue
		}
		received++
		touched = true
		if s.At.IsZero() {
			s.At = now
		}
		c.samples[sampleKey(s)] = s
	}
	cutoff := now.Add(-c.staleAfter)
	stale := 0
	for k, s := range c.samples {
		if s.At.Before(cutoff) {
			delete(c.samples, k)
			stale++
		}
	}
	c.samplesGauge.Set(float64(len(c.samples)))
	if stale > 0 {
		c.staleDropped.Add(float64(stale))
	}
	if !touched {
		c.ignored.Inc()
		c.logCommit(commitView{received: received, stale: stale, edges: len(c.edges)}, true)
		return false, nil
	}
	held := make([]sample, 0, len(c.samples))
	var ts time.Time
	for _, s := range c.samples {
		held = append(held, s)
		if s.At.After(ts) {
			ts = s.At
		}
	}
	built, st := observeSamples(held)
	c.edges = reconcile(built)
	c.edgesGauge.Set(float64(len(c.edges)))
	c.unmatched.Set(float64(st.Unmatched))
	c.unresolved.Set(float64(st.Unresolved))
	c.byEvidence.Reset()
	evidence := map[string]int{}
	for _, e := range c.edges {
		ev := e.Evidence
		if ev == "" {
			ev = "unknown"
		}
		evidence[ev]++
	}
	for ev, n := range evidence {
		c.byEvidence.WithLabelValues(ev).Set(float64(n))
	}
	nowUnix := float64(now.Unix())
	c.lastReconcile.Set(nowUnix)
	if len(c.edges) > 0 {
		c.lastGraph.Set(nowUnix)
	}
	if ts.IsZero() {
		ts = now
	}
	c.logCommit(commitView{
		received:     received,
		stale:        stale,
		edges:        len(c.edges),
		observeStats: st,
	}, false)
	return true, graphSeries(c.edges, ts)
}

func sampleKey(s sample) string {
	keys := make([]string, 0, len(s.Labels))
	for k := range s.Labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	b := s.Name
	for _, k := range keys {
		b += "\xff" + k + "=" + s.Labels[k]
	}
	return b
}

type commitView struct {
	received int
	stale    int
	edges    int
	observeStats
}

func (c *Component) logCommit(v commitView, kept bool) {
	if c.opts.Logger == nil {
		return
	}
	args := []any{
		"received", v.received,
		"matched", v.Matched,
		"helpers", v.Helpers,
		"unmatched", v.Unmatched,
		"no_reporter", v.NoReporter,
		"noisy", v.Noisy,
		"no_neighbor", v.NoNeighbor,
		"not_established", v.NotEstablished,
		"self", v.Self,
		"resolved", v.Resolved,
		"unresolved", v.Unresolved,
		"stale_dropped", v.stale,
		"edges", v.edges,
		"samples_held", len(c.samples),
	}
	switch {
	case kept:
		c.opts.Logger.Debug("network topology kept last graph", args...)
	case v.edges == 0 && (v.Matched > 0 || v.Unmatched > 0):
		c.opts.Logger.Warn("network topology samples produced no edges", args...)
	case v.Unmatched > 0:
		c.opts.Logger.Warn("network topology samples matched no family", args...)
	default:
		c.opts.Logger.Info("reconciled network topology", args...)
	}
}

func graphSeries(edges []edge, ts time.Time) []seriesPoint {
	t := ts.UnixMilli()
	var out []seriesPoint
	for _, dev := range devicesFrom(edges) {
		out = append(out, seriesPoint{
			labels: labels.FromStrings(
				"__name__", "network_topology_device_info",
				"device_id", dev,
				"vendor", "unknown",
				"model", "unknown",
				"os_version", "unknown",
				"site", "unknown",
				// otelcol.receiver.prometheus rejects series without these.
				"job", "network-topology",
				"instance", "alloy",
			),
			t: t,
			v: 1,
		})
	}
	for _, e := range edges {
		out = append(out, seriesPoint{
			labels: labels.FromStrings(
				"__name__", "network_topology_edge_info",
				"src_device", e.SrcDevice,
				"src_port", orEmpty(e.SrcPort),
				"dst_device", e.DstDevice,
				"dst_port", orEmpty(e.DstPort),
				"discovery_proto", e.Proto,
				"link_kind", e.LinkKind,
				"direction", e.Direction,
				"inference", "alloy",
				"evidence", e.Evidence,
				"session_type", orEmpty(e.SessionType),
				"remote_as", orEmpty(e.RemoteAS),
				"peer_group", orEmpty(e.PeerGroup),
				"job", "network-topology",
				"instance", "alloy",
			),
			t: t,
			v: 1,
		})
	}
	return out
}

func orEmpty(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

type receive struct {
	comp *Component
}

func (r *receive) Appender(ctx context.Context) storage.Appender {
	r.comp.mut.Lock()
	fan := r.comp.fanout
	r.comp.mut.Unlock()
	var child storage.Appender
	if fan != nil {
		child = fan.Appender(ctx)
	}
	return &appender{comp: r.comp, child: child}
}

type appender struct {
	comp    *Component
	child   storage.Appender
	batch   []sample
	touched bool
	latest  time.Time
}

func (a *appender) SetOptions(*storage.AppendOptions) {}

func (a *appender) Append(_ storage.SeriesRef, l labels.Labels, t int64, v float64) (storage.SeriesRef, error) {
	if value.IsStaleNaN(v) {
		return 0, nil
	}
	name := l.Get(labels.MetricName)
	if name == "" || !relevant(name) {
		return 0, nil
	}
	lbls := make(map[string]string, l.Len())
	l.Range(func(lb labels.Label) {
		if lb.Name != labels.MetricName {
			lbls[lb.Name] = lb.Value
		}
	})
	at := time.UnixMilli(t)
	if at.After(a.latest) {
		a.latest = at
	}
	a.batch = append(a.batch, sample{Name: name, Labels: lbls, Value: v, At: at})
	a.touched = true
	return 0, nil
}

func (a *appender) Commit() error {
	now := a.latest
	if now.IsZero() {
		now = time.Now()
	}
	touched, points := a.comp.ingest(a.batch, now)
	if touched && a.child != nil {
		for i, p := range points {
			if _, err := a.child.Append(0, p.labels, p.t, p.v); err != nil {
				if a.comp.opts.Logger != nil {
					a.comp.opts.Logger.Error("network topology forward failed", "err", err, "written", i, "points", len(points))
				}
				_ = a.child.Rollback()
				return err
			}
		}
	}
	if a.child == nil {
		return nil
	}
	return a.child.Commit()
}

func (a *appender) Rollback() error {
	if a.child == nil {
		return nil
	}
	return a.child.Rollback()
}

func (a *appender) AppendExemplar(storage.SeriesRef, labels.Labels, exemplar.Exemplar) (storage.SeriesRef, error) {
	return 0, nil
}

func (a *appender) UpdateMetadata(storage.SeriesRef, labels.Labels, metadata.Metadata) (storage.SeriesRef, error) {
	return 0, nil
}

func (a *appender) AppendHistogram(storage.SeriesRef, labels.Labels, int64, *histogram.Histogram, *histogram.FloatHistogram) (storage.SeriesRef, error) {
	return 0, nil
}

func (a *appender) AppendSTZeroSample(storage.SeriesRef, labels.Labels, int64, int64) (storage.SeriesRef, error) {
	return 0, nil
}

func (a *appender) AppendHistogramSTZeroSample(storage.SeriesRef, labels.Labels, int64, int64, *histogram.Histogram, *histogram.FloatHistogram) (storage.SeriesRef, error) {
	return 0, nil
}
