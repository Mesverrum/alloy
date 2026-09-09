package syslog

import (
	"testing"

	"github.com/grafana/alloy/internal/component/common/devicejoin"
	"github.com/grafana/alloy/internal/component/discovery"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/plog"
)

func TestStampSyslogJoin(t *testing.T) {
	idx := devicejoin.NewIndex([]discovery.Target{
		discovery.NewTargetFromMap(map[string]string{
			"address":     "10.0.0.2",
			"device_name": "spine1",
			"snmp_group":  "hq",
		}),
	})

	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	rec := rl.ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
	rec.Attributes().PutStr("net.peer.ip", "10.0.0.2")

	stampSyslogJoin(ld, idx, nil)

	got, _ := rec.Attributes().Get("device_name")
	require.Equal(t, "spine1", got.AsString())
	got, _ = rec.Attributes().Get("snmp_group")
	require.Equal(t, "hq", got.AsString())
}

func TestStampSyslogJoinHostname(t *testing.T) {
	idx := devicejoin.NewIndex([]discovery.Target{
		discovery.NewTargetFromMap(map[string]string{
			"address":     "10.0.0.3",
			"device_name": "leaf1",
		}),
	})

	ld := plog.NewLogs()
	rec := ld.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
	rec.Attributes().PutStr("hostname", "leaf1")

	stampSyslogJoin(ld, idx, nil)

	got, _ := rec.Attributes().Get("device_name")
	require.Equal(t, "leaf1", got.AsString())
}

func TestStampSyslogJoinEmptyCatalog(t *testing.T) {
	ld := plog.NewLogs()
	rec := ld.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
	rec.Attributes().PutStr("net.peer.ip", "10.0.0.2")
	stampSyslogJoin(ld, devicejoin.NewIndex(nil), nil)
	_, ok := rec.Attributes().Get("device_name")
	require.False(t, ok)
}

func TestListenConfigEqualIgnoresTargets(t *testing.T) {
	a := Arguments{Protocol: "rfc3164", OnError: "send"}
	b := a
	a.Targets = []discovery.Target{
		discovery.NewTargetFromMap(map[string]string{"address": "10.0.0.2", "device_name": "spine1"}),
	}
	b.Targets = []discovery.Target{
		discovery.NewTargetFromMap(map[string]string{"address": "10.0.0.3", "device_name": "leaf1"}),
	}
	require.True(t, listenConfigEqual(a, b))
	b.OnError = "drop"
	require.False(t, listenConfigEqual(a, b))
}
