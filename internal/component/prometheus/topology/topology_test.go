package topology

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/prometheus/model/exemplar"
	"github.com/prometheus/prometheus/model/histogram"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/metadata"
	"github.com/prometheus/prometheus/storage"
	"github.com/stretchr/testify/require"

	"github.com/grafana/alloy/internal/component"
	"github.com/grafana/alloy/internal/service/labelstore"
	"github.com/grafana/alloy/internal/util"
)

func TestLLDPJoinAndReconcile(t *testing.T) {
	now := time.Now()
	samples := []sample{
		{
			Name: "snmp_lldpLocPortDesc",
			Labels: map[string]string{
				"device_name":     "leaf1",
				"lldpLocPortNum":  "1",
				"lldpLocPortDesc": "ethernet-1/49",
			},
			Value: 1, At: now,
		},
		{
			Name: "snmp_lldpRemPortIdSubtype",
			Labels: map[string]string{
				"device_name":          "leaf1",
				"lldpRemTimeMark":      "0",
				"lldpRemLocalPortNum":  "1",
				"lldpRemIndex":         "1",
				"lldpRemPortIdSubtype": "interfaceName",
			},
			Value: 1, At: now,
		},
		{
			Name: "snmp_lldpRemSysName",
			Labels: map[string]string{
				"device_name":         "leaf1",
				"lldpRemTimeMark":     "0",
				"lldpRemLocalPortNum": "1",
				"lldpRemIndex":        "1",
				"lldpRemSysName":      "spine1",
			},
			Value: 1, At: now,
		},
		{
			Name: "snmp_lldpRemPortId",
			Labels: map[string]string{
				"device_name":         "leaf1",
				"lldpRemTimeMark":     "0",
				"lldpRemLocalPortNum": "1",
				"lldpRemIndex":        "1",
				"lldpRemPortId":       "ethernet-1/1",
			},
			Value: 1, At: now,
		},
		{
			Name: "snmp_lldpRemSysName",
			Labels: map[string]string{
				"device_name":         "leaf1",
				"lldpRemTimeMark":     "0",
				"lldpRemLocalPortNum": "2",
				"lldpRemIndex":        "1",
				"lldpRemSysName":      "SEP-phone-1",
			},
			Value: 1, At: now,
		},
	}
	got := reconcile(edgesFromSamples(samples))
	require.Len(t, got, 1)
	require.Equal(t, "leaf1", got[0].SrcDevice)
	require.Equal(t, "ethernet-1/49", got[0].SrcPort)
	require.Equal(t, "spine1", got[0].DstDevice)
	require.Equal(t, "ethernet-1/1", got[0].DstPort)
	require.Equal(t, "lldp", got[0].Proto)
	require.Equal(t, "unidirectional", got[0].Direction)
}

func TestExporterOctetString(t *testing.T) {
	now := time.Now()
	// ethernet-1/49 as snmp_exporter OctetString (0x + hex).
	locID := "0x" + hexEncode("ethernet-1/49")
	samples := []sample{
		{
			Name: "snmp_lldpLocPortIdSubtype_info",
			Labels: map[string]string{
				"device_name": "leaf1", "lldpLocPortNum": "1",
				"snmp_lldpLocPortIdSubtype": "interfaceName",
			},
			Value: 1, At: now,
		},
		{
			Name: "snmp_lldpLocPortId",
			Labels: map[string]string{
				"device_name": "leaf1", "lldpLocPortNum": "1",
				"snmp_lldpLocPortId": locID,
			},
			Value: 1, At: now,
		},
		{
			Name: "snmp_lldpRemPortIdSubtype_info",
			Labels: map[string]string{
				"device_name": "leaf1", "lldpRemTimeMark": "0", "lldpRemLocalPortNum": "1", "lldpRemIndex": "1",
				"snmp_lldpRemPortIdSubtype": "macAddress",
			},
			Value: 1, At: now,
		},
		{
			Name: "snmp_lldpRemSysName",
			Labels: map[string]string{
				"device_name": "leaf1", "lldpRemTimeMark": "0", "lldpRemLocalPortNum": "1", "lldpRemIndex": "1",
				"snmp_lldpRemSysName": "spine1",
			},
			Value: 1, At: now,
		},
		{
			Name: "snmp_lldpRemPortId",
			Labels: map[string]string{
				"device_name": "leaf1", "lldpRemTimeMark": "0", "lldpRemLocalPortNum": "1", "lldpRemIndex": "1",
				"snmp_lldpRemPortId": "0xAABBCCDDEEFF",
			},
			Value: 1, At: now,
		},
	}
	got := reconcile(edgesFromSamples(samples))
	require.Len(t, got, 1)
	require.Equal(t, "leaf1", got[0].SrcDevice)
	require.Equal(t, "ethernet-1/49", got[0].SrcPort)
	require.Equal(t, "spine1", got[0].DstDevice)
	require.Equal(t, "aa:bb:cc:dd:ee:ff", got[0].DstPort)
}

func hexEncode(s string) string {
	return strings.ToUpper(hex.EncodeToString([]byte(s)))
}

func TestPortNameCollapse(t *testing.T) {
	edges := []edge{
		{SrcDevice: "a", SrcPort: "GigabitEthernet0/1", DstDevice: "b", DstPort: "Eth1", Proto: "lldp", Rank: rankLLDP},
		{SrcDevice: "b", SrcPort: "Eth1", DstDevice: "a", DstPort: "Gi0/1", Proto: "cdp", Rank: rankCDP},
	}
	got := reconcile(edges)
	require.Len(t, got, 1)
	require.Equal(t, "lldp", got[0].Proto)
	require.Equal(t, "bidirectional", got[0].Direction)
	require.Equal(t, "Gi0/1", got[0].SrcPort)
}

func TestMACSubtype(t *testing.T) {
	now := time.Now()
	samples := []sample{
		{
			Name: "snmp_lldpRemPortIdSubtype",
			Labels: map[string]string{
				"device_name": "leaf1", "lldpRemTimeMark": "0", "lldpRemLocalPortNum": "1", "lldpRemIndex": "1",
			},
			Value: 3, At: now,
		},
		{
			Name: "snmp_lldpRemSysName",
			Labels: map[string]string{
				"device_name": "leaf1", "lldpRemTimeMark": "0", "lldpRemLocalPortNum": "1", "lldpRemIndex": "1",
				"lldpRemSysName": "cam",
			},
			Value: 1, At: now,
		},
		{
			Name: "snmp_lldpRemPortId",
			Labels: map[string]string{
				"device_name": "leaf1", "lldpRemTimeMark": "0", "lldpRemLocalPortNum": "1", "lldpRemIndex": "1",
				"lldpRemPortId": "aabbccddeeff",
			},
			Value: 1, At: now,
		},
	}
	got := reconcile(edgesFromSamples(samples))
	require.Len(t, got, 1)
	ports := map[string]string{got[0].SrcDevice: got[0].SrcPort, got[0].DstDevice: got[0].DstPort}
	require.Equal(t, "aa:bb:cc:dd:ee:ff", ports["cam"])
	require.Equal(t, "1", ports["leaf1"])
}

func TestBGPEstablishedString(t *testing.T) {
	now := time.Now()
	up := reconcile(edgesFromSamples([]sample{{
		Name: "snmp_tBgpPeerNgConnState",
		Labels: map[string]string{
			"device_name": "spine1", "tBgpPeerNgAddress": "10.0.0.2",
			"tBgpPeerNgConnState": "established", "tBgpPeerNgPeerAS": "65002", "local_as": "65001",
		},
		Value: 1, At: now,
	}}))
	require.Len(t, up, 1)
	require.Equal(t, "ebgp", up[0].SessionType)
	require.Equal(t, "65002", up[0].RemoteAS)
	require.Equal(t, "unidirectional", up[0].Direction)

	down := edgesFromSamples([]sample{{
		Name: "snmp_tBgpPeerNgConnState",
		Labels: map[string]string{
			"device_name": "spine1", "tBgpPeerNgAddress": "10.0.0.3", "tBgpPeerNgConnState": "idle",
		},
		Value: 1, At: now,
	}})
	require.Empty(t, down)
}

func TestComponentEmitsGraph(t *testing.T) {
	var got []labels.Labels
	sink := &capture{fn: func(l labels.Labels) { got = append(got, l) }}
	comp := newTestComponent(t, sink)

	ctx := context.Background()
	app := comp.receiver.Appender(ctx)
	_, err := app.Append(0, labels.FromStrings(
		"__name__", "snmp_lldpRemSysName",
		"device_name", "leaf1",
		"lldpRemTimeMark", "0",
		"lldpRemLocalPortNum", "1",
		"lldpRemIndex", "1",
		"lldpRemSysName", "spine1",
		"ifName", "ethernet-1/49",
	), time.Now().UnixMilli(), 1)
	require.NoError(t, err)
	_, err = app.Append(0, labels.FromStrings(
		"__name__", "snmp_lldpRemPortId",
		"device_name", "leaf1",
		"lldpRemTimeMark", "0",
		"lldpRemLocalPortNum", "1",
		"lldpRemIndex", "1",
		"lldpRemPortId", "ethernet-1/1",
	), time.Now().UnixMilli(), 1)
	require.NoError(t, err)
	require.NoError(t, app.Commit())

	var edges int
	for _, l := range got {
		if l.Get("__name__") == "network_topology_edge_info" {
			edges++
			require.Equal(t, "leaf1", l.Get("src_device"))
			require.Equal(t, "ethernet-1/49", l.Get("src_port"))
			require.Equal(t, "spine1", l.Get("dst_device"))
			require.Equal(t, "network-topology", l.Get("job"))
			require.Equal(t, "alloy", l.Get("instance"))
		}
	}
	require.Equal(t, 1, edges)

	// A non-topology scrape must not clear the graph.
	got = nil
	app = comp.receiver.Appender(ctx)
	_, err = app.Append(0, labels.FromStrings("__name__", "up", "device_name", "leaf1"), time.Now().UnixMilli(), 1)
	require.NoError(t, err)
	require.NoError(t, app.Commit())
	require.Empty(t, got)
	comp.mut.Lock()
	require.Len(t, comp.edges, 1)
	comp.mut.Unlock()
}

func TestDebugMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	sink := &capture{fn: func(labels.Labels) {}}
	comp, err := New(component.Options{
		ID:            "prometheus.network_topology.test",
		Logger:        util.TestAlloyLogger(t).Slog(),
		OnStateChange: func(component.Exports) {},
		Registerer:    reg,
		GetServiceData: func(name string) (any, error) {
			if name == labelstore.ServiceName {
				return labelstore.New(nil, prometheus.NewRegistry()), nil
			}
			return nil, fmt.Errorf("service not found %s", name)
		},
	}, Arguments{ForwardTo: []storage.Appendable{sink}, StaleAfter: time.Hour})
	require.NoError(t, err)

	ctx := context.Background()
	app := comp.receiver.Appender(ctx)
	now := time.Now().UnixMilli()
	_, err = app.Append(0, labels.FromStrings(
		"__name__", "snmp_lldpRemSysName",
		"device_name", "leaf1",
		"lldpRemTimeMark", "0", "lldpRemLocalPortNum", "1", "lldpRemIndex", "1",
		"lldpRemSysName", "spine1", "ifName", "ethernet-1/49",
	), now, 1)
	require.NoError(t, err)
	_, err = app.Append(0, labels.FromStrings(
		"__name__", "snmp_lldpRemPortId",
		"device_name", "leaf1",
		"lldpRemTimeMark", "0", "lldpRemLocalPortNum", "1", "lldpRemIndex", "1",
		"lldpRemPortId", "ethernet-1/1",
	), now, 1)
	require.NoError(t, err)
	_, err = app.Append(0, labels.FromStrings(
		"__name__", "snmp_lldpLocPortDesc",
		"device_name", "leaf1", "lldpLocPortNum", "1", "snmp_lldpLocPortDesc", "ethernet-1/49",
	), now, 1)
	require.NoError(t, err)
	require.NoError(t, app.Commit())

	require.Equal(t, 3.0, metricValue(t, reg, "alloy_prometheus_network_topology_samples", ""))
	require.Equal(t, 1.0, metricValue(t, reg, "alloy_prometheus_network_topology_edges", ""))
	require.Equal(t, 0.0, metricValue(t, reg, "alloy_prometheus_network_topology_unmatched_samples", ""))
	require.Equal(t, 1.0, metricValue(t, reg, "alloy_prometheus_network_topology_edges_by_evidence", "lldp_rem"))
	require.Greater(t, metricValue(t, reg, "alloy_prometheus_network_topology_last_reconcile_timestamp_seconds", ""), 0.0)
	graphAt := metricValue(t, reg, "alloy_prometheus_network_topology_last_graph_timestamp_seconds", "")
	require.Greater(t, graphAt, 0.0)
	require.Equal(t, 0.0, metricValue(t, reg, "alloy_prometheus_network_topology_ignored_commits_total", ""))

	app = comp.receiver.Appender(ctx)
	_, err = app.Append(0, labels.FromStrings("__name__", "up", "device_name", "leaf1"), time.Now().UnixMilli(), 1)
	require.NoError(t, err)
	require.NoError(t, app.Commit())

	require.Equal(t, 1.0, metricValue(t, reg, "alloy_prometheus_network_topology_ignored_commits_total", ""))
	require.Equal(t, 1.0, metricValue(t, reg, "alloy_prometheus_network_topology_edges", ""))
	require.Equal(t, graphAt, metricValue(t, reg, "alloy_prometheus_network_topology_last_graph_timestamp_seconds", ""))
}

func metricValue(t *testing.T, reg *prometheus.Registry, name, evidence string) float64 {
	t.Helper()
	mfs, err := reg.Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			if evidence != "" && metricLabel(m, "evidence") != evidence {
				continue
			}
			if g := m.GetGauge(); g != nil {
				return g.GetValue()
			}
			if c := m.GetCounter(); c != nil {
				return c.GetValue()
			}
		}
	}
	t.Fatalf("metric %s evidence %q not found", name, evidence)
	return 0
}

func metricLabel(m *dto.Metric, name string) string {
	for _, l := range m.GetLabel() {
		if l.GetName() == name {
			return l.GetValue()
		}
	}
	return ""
}

func newTestComponent(t *testing.T, sink storage.Appendable) *Component {
	t.Helper()
	c, err := New(component.Options{
		ID:            "prometheus.network_topology.test",
		Logger:        util.TestAlloyLogger(t).Slog(),
		OnStateChange: func(e component.Exports) {},
		Registerer:    prometheus.NewRegistry(),
		GetServiceData: func(name string) (any, error) {
			if name == labelstore.ServiceName {
				return labelstore.New(nil, prometheus.NewRegistry()), nil
			}
			return nil, fmt.Errorf("service not found %s", name)
		},
	}, Arguments{ForwardTo: []storage.Appendable{sink}, StaleAfter: time.Hour})
	require.NoError(t, err)
	return c
}

type capture struct {
	fn func(labels.Labels)
}

func (c *capture) Appender(context.Context) storage.Appender { return &captureApp{fn: c.fn} }

type captureApp struct {
	fn func(labels.Labels)
}

func (c *captureApp) Append(_ storage.SeriesRef, l labels.Labels, _ int64, _ float64) (storage.SeriesRef, error) {
	c.fn(l)
	return 0, nil
}
func (c *captureApp) Commit() error                     { return nil }
func (c *captureApp) Rollback() error                   { return nil }
func (c *captureApp) SetOptions(*storage.AppendOptions) {}
func (c *captureApp) AppendExemplar(storage.SeriesRef, labels.Labels, exemplar.Exemplar) (storage.SeriesRef, error) {
	return 0, nil
}
func (c *captureApp) UpdateMetadata(storage.SeriesRef, labels.Labels, metadata.Metadata) (storage.SeriesRef, error) {
	return 0, nil
}
func (c *captureApp) AppendHistogram(storage.SeriesRef, labels.Labels, int64, *histogram.Histogram, *histogram.FloatHistogram) (storage.SeriesRef, error) {
	return 0, nil
}
func (c *captureApp) AppendSTZeroSample(storage.SeriesRef, labels.Labels, int64, int64) (storage.SeriesRef, error) {
	return 0, nil
}
func (c *captureApp) AppendHistogramSTZeroSample(storage.SeriesRef, labels.Labels, int64, int64, *histogram.Histogram, *histogram.FloatHistogram) (storage.SeriesRef, error) {
	return 0, nil
}
