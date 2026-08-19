package netflow

import (
	"testing"

	"github.com/grafana/alloy/internal/component/common/devicejoin"
	"github.com/grafana/alloy/internal/component/discovery"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/plog"
)

func TestStampFlowJoin(t *testing.T) {
	idx := devicejoin.NewIndex([]discovery.Target{
		discovery.NewTargetFromMap(map[string]string{
			"address":      "10.0.0.2",
			"device_name":  "spine1",
			"snmp_group":   "hq",
			"snmp_aliases": "192.168.1.1",
		}),
		discovery.NewTargetFromMap(map[string]string{
			"address":     "172.17.0.1",
			"device_name": "client1",
		}),
	})

	ld := plog.NewLogs()
	rec := ld.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
	rec.Attributes().PutStr("flow.sampler_address", "192.168.1.1")
	rec.Attributes().PutStr("source.address", "172.17.0.1")
	rec.Attributes().PutStr("destination.address", "8.8.8.8")

	stampFlowJoin(ld, idx, nil)

	attrs := rec.Attributes()
	got, _ := attrs.Get("device_name")
	require.Equal(t, "spine1", got.AsString())
	got, _ = attrs.Get("snmp_group")
	require.Equal(t, "hq", got.AsString())
	got, _ = attrs.Get("src_device")
	require.Equal(t, "client1", got.AsString())
	_, hasDst := attrs.Get("dst_device")
	require.False(t, hasDst)
}

func TestStampFlowJoinEmptyCatalog(t *testing.T) {
	ld := plog.NewLogs()
	rec := ld.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
	rec.Attributes().PutStr("flow.sampler_address", "10.0.0.2")
	stampFlowJoin(ld, devicejoin.NewIndex(nil), nil)
	_, ok := rec.Attributes().Get("device_name")
	require.False(t, ok)
}

func TestListenConfigEqualIgnoresTargets(t *testing.T) {
	a := Arguments{Scheme: "netflow", Port: 2055, Sockets: 1, Workers: 2}
	b := a
	a.Targets = []discovery.Target{
		discovery.NewTargetFromMap(map[string]string{"address": "10.0.0.2", "device_name": "spine1"}),
	}
	b.Targets = []discovery.Target{
		discovery.NewTargetFromMap(map[string]string{"address": "10.0.0.3", "device_name": "leaf1"}),
	}
	require.True(t, listenConfigEqual(a, b))
	b.Port = 2056
	require.False(t, listenConfigEqual(a, b))
}
