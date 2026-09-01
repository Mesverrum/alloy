package snmptrap

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/plog"

	"github.com/grafana/alloy/internal/component"
	"github.com/grafana/alloy/internal/component/common/devicejoin"
	"github.com/grafana/alloy/internal/component/discovery"
	"github.com/grafana/alloy/internal/component/otelcol"
	"github.com/grafana/alloy/internal/component/otelcol/internal/fakeconsumer"
	"github.com/grafana/alloy/internal/runtime/componenttest"
	"github.com/grafana/alloy/internal/runtime/logging"
	"github.com/grafana/alloy/internal/service/livedebugging"
	"github.com/grafana/alloy/internal/snmppaths"
	traplib "github.com/grafana/alloy/internal/snmptrap"
	"github.com/grafana/alloy/syntax"
)

func testOpts() component.Options {
	return component.Options{
		Logger:     logging.NewSlogNop(),
		Registerer: prometheus.NewRegistry(),
		OnStateChange: func(e component.Exports) {
		},
		GetServiceData: func(name string) (any, error) {
			if name == livedebugging.ServiceName {
				return livedebugging.NewLiveDebugging(), nil
			}
			return nil, context.Canceled
		},
	}
}

func TestUnmarshalArguments(t *testing.T) {
	var args Arguments
	err := syntax.Unmarshal([]byte(`
		listen_address    = "0.0.0.0:1620"
		communities       = ["public", "lab"]
		include_community = true
		drop_undefined    = false
		mib_paths         = ["/etc/alloy/mibs"]
		attributes        = { job = "snmptrap" }
		output { }

		v3 {
			user            = "trapuser"
			security_level  = "authPriv"
			auth_protocol   = "SHA"
			auth_password   = "authsecret"
			priv_protocol   = "AES"
			priv_password   = "privsecret"
		}
	`), &args)
	require.NoError(t, err)
	require.Equal(t, "0.0.0.0:1620", args.ListenAddress)
	require.Equal(t, []string{"public", "lab"}, args.Communities)
	require.True(t, args.IncludeCommunity)
	require.NotNil(t, args.V3)
	require.Equal(t, "trapuser", args.V3.User)
	require.NoError(t, args.Validate())
}

func TestUnmarshalDefaultsAcceptAllCommunities(t *testing.T) {
	var args Arguments
	err := syntax.Unmarshal([]byte(`
		output { }
	`), &args)
	require.NoError(t, err)
	require.Equal(t, "0.0.0.0:1620", args.ListenAddress)
	require.Equal(t, []string{snmppaths.MIBDir}, args.MIBPaths)
	require.Empty(t, args.Communities)
}

func TestReceiveV2Trap(t *testing.T) {
	addr := componenttest.GetFreeAddr(t)
	logCh := make(chan plog.Logs, 1)
	args := Arguments{
		ListenAddress: addr,
		MIBPaths:      []string{},
		Attributes:    map[string]string{"job": "snmptrap"},
		Output: &ConsumerArguments{
			Logs: []otelcol.Consumer{&fakeconsumer.Consumer{
				ConsumeLogsFunc: func(_ context.Context, ld plog.Logs) error {
					logCh <- ld
					return nil
				},
			}},
		},
	}

	c, err := New(testOpts(), args)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	go func() { _ = c.Run(ctx) }()
	time.Sleep(200 * time.Millisecond)

	host, portStr, ok := strings.Cut(addr, ":")
	require.True(t, ok)
	port, err := strconv.ParseUint(portStr, 10, 16)
	require.NoError(t, err)

	snmp := &gosnmp.GoSNMP{
		Target:    host,
		Port:      uint16(port),
		Community: "public",
		Version:   gosnmp.Version2c,
		Timeout:   2 * time.Second,
		Retries:   1,
	}
	require.NoError(t, snmp.Connect())
	defer snmp.Conn.Close()

	_, err = snmp.SendTrap(gosnmp.SnmpTrap{
		Variables: []gosnmp.SnmpPDU{
			{Name: "1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(42)},
			{Name: "1.3.6.1.6.3.1.1.4.1.0", Type: gosnmp.ObjectIdentifier, Value: "1.3.6.1.6.3.1.1.5.1"},
			{Name: "1.3.6.1.2.1.1.5.0", Type: gosnmp.OctetString, Value: []byte("spine1")},
		},
	})
	require.NoError(t, err)

	select {
	case <-ctx.Done():
		t.Fatal("timed out waiting for trap log")
	case ld := <-logCh:
		require.Equal(t, 1, ld.LogRecordCount())
		lr := ld.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
		job, ok := lr.Attributes().Get("job")
		require.True(t, ok)
		require.Equal(t, "snmptrap", job.AsString())
		oid, ok := lr.Attributes().Get("trap_oid")
		require.True(t, ok)
		require.Equal(t, "1.3.6.1.6.3.1.1.5.1", oid.AsString())
		require.Contains(t, lr.Body().AsString(), "spine1")
		var rec map[string]any
		require.NoError(t, json.Unmarshal([]byte(lr.Body().AsString()), &rec))
		require.Equal(t, "2c", rec["version"])
	}
}

func TestStampJoinPrimaryAndAlias(t *testing.T) {
	idx := devicejoinIndex(t)
	m := newRecvMetrics(prometheus.NewRegistry())

	rec := traplibRecord("10.0.0.10", "")
	stampJoin(&rec, idx, m)
	require.Equal(t, "spine1", rec.DeviceName)
	require.Equal(t, "hq", rec.SnmpGroup)

	rec2 := traplibRecord("8.8.8.8", "10.0.0.2")
	stampJoin(&rec2, idx, m)
	require.Equal(t, "spine1", rec2.DeviceName)

	rec3 := traplibRecord("1.2.3.4", "")
	stampJoin(&rec3, idx, m)
	require.Empty(t, rec3.DeviceName)
}

func TestUpdateTargetsDoesNotRestartListener(t *testing.T) {
	addr := componenttest.GetFreeAddr(t)
	args := Arguments{
		ListenAddress: addr,
		MIBPaths:      []string{},
		Output:        &ConsumerArguments{},
	}
	c, err := New(testOpts(), args)
	require.NoError(t, err)
	first := c.lastListen

	args.Targets = []discovery.Target{
		discovery.NewTargetFromMap(map[string]string{
			"address":     "10.0.0.2",
			"device_name": "spine1",
		}),
	}
	require.NoError(t, c.Update(args))
	require.Equal(t, first, c.lastListen)
	require.Equal(t, 1, c.join.Load().Len())
}

func devicejoinIndex(t *testing.T) *devicejoin.Index {
	t.Helper()
	return devicejoin.NewIndex([]discovery.Target{
		discovery.NewTargetFromMap(map[string]string{
			"address":      "10.0.0.2",
			"device_name":  "spine1",
			"snmp_group":   "hq",
			"snmp_aliases": "10.0.0.10",
		}),
	})
}

func traplibRecord(source, agent string) traplib.Record {
	return traplib.Record{Source: source, AgentAddress: agent}
}
