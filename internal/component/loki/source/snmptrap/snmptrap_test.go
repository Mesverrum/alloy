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

	"github.com/grafana/alloy/internal/component"
	"github.com/grafana/alloy/internal/component/common/devicejoin"
	"github.com/grafana/alloy/internal/component/common/loki"
	"github.com/grafana/alloy/internal/component/discovery"
	"github.com/grafana/alloy/internal/runtime/componenttest"
	"github.com/grafana/alloy/internal/runtime/logging"
	traplib "github.com/grafana/alloy/internal/snmptrap"
	"github.com/grafana/alloy/syntax"
)

func TestUnmarshalArguments(t *testing.T) {
	var args Arguments
	err := syntax.Unmarshal([]byte(`
		listen_address    = "0.0.0.0:1620"
		communities       = ["public", "lab"]
		include_community = true
		drop_undefined    = false
		mib_paths         = ["/etc/alloy/mibs"]
		labels            = { site = "hq" }
		forward_to        = []

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
		forward_to = []
	`), &args)
	require.NoError(t, err)
	require.Equal(t, "0.0.0.0:1620", args.ListenAddress)
	require.Empty(t, args.Communities)
	require.True(t, communityAllowed(args.Communities, "anything"))
	require.True(t, communityAllowed(args.Communities, ""))
}

func TestCommunityAllowlist(t *testing.T) {
	allow := []string{"public"}
	require.True(t, communityAllowed(allow, "public"))
	require.False(t, communityAllowed(allow, "private"))
	require.False(t, communityAllowed(allow, ""))
}

func TestReceiveV2Trap(t *testing.T) {
	opts := component.Options{
		Logger:        logging.NewSlogNop(),
		Registerer:    prometheus.NewRegistry(),
		OnStateChange: func(e component.Exports) {},
	}

	ch1 := loki.NewLogsReceiver()
	addr := componenttest.GetFreeAddr(t)
	args := Arguments{
		ListenAddress: addr,
		ForwardTo:     []loki.LogsReceiver{ch1},
		Labels:        map[string]string{"job": "snmptrap"},
	}

	c, err := New(opts, args)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	go func() { _ = c.Run(ctx) }()

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
	case e := <-ch1.Chan():
		require.Equal(t, "snmptrap", string(e.Labels["job"]))
		require.NotContains(t, e.Labels, "__snmptrap_oid")
		require.Contains(t, e.Entry.Line, "1.3.6.1.6.3.1.1.5.1")
		require.Contains(t, e.Entry.Line, "spine1")
		var rec map[string]any
		require.NoError(t, json.Unmarshal([]byte(e.Entry.Line), &rec))
		require.Equal(t, "2c", rec["version"])
		require.Equal(t, "1.3.6.1.6.3.1.1.5.1", rec["trap_oid"])
	}

	mfs, err := opts.Registerer.(*prometheus.Registry).Gather()
	require.NoError(t, err)
	var gotRecv, gotFwd float64
	for _, mf := range mfs {
		switch mf.GetName() {
		case "loki_source_snmptrap_received_total":
			for _, met := range mf.GetMetric() {
				gotRecv += met.GetCounter().GetValue()
			}
		case "loki_source_snmptrap_entries_total":
			gotFwd = mf.GetMetric()[0].GetCounter().GetValue()
		}
	}
	require.GreaterOrEqual(t, gotRecv, 1.0)
	require.GreaterOrEqual(t, gotFwd, 1.0)
}

func TestDropUndefined(t *testing.T) {
	opts := component.Options{
		Logger:        logging.NewSlogNop(),
		Registerer:    prometheus.NewRegistry(),
		OnStateChange: func(e component.Exports) {},
	}
	ch1 := loki.NewLogsReceiver()
	addr := componenttest.GetFreeAddr(t)
	args := Arguments{
		ListenAddress: addr,
		ForwardTo:     []loki.LogsReceiver{ch1},
		DropUndefined: true,
	}
	c, err := New(opts, args)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	go func() { _ = c.Run(ctx) }()

	host, portStr, _ := strings.Cut(addr, ":")
	port, _ := strconv.ParseUint(portStr, 10, 16)
	snmp := &gosnmp.GoSNMP{
		Target: host, Port: uint16(port), Community: "public",
		Version: gosnmp.Version2c, Timeout: time.Second, Retries: 0,
	}
	require.NoError(t, snmp.Connect())
	defer snmp.Conn.Close()
	_, err = snmp.SendTrap(gosnmp.SnmpTrap{
		Variables: []gosnmp.SnmpPDU{
			{Name: "1.3.6.1.6.3.1.1.4.1.0", Type: gosnmp.ObjectIdentifier, Value: "1.3.6.1.6.3.1.1.5.1"},
		},
	})
	require.NoError(t, err)

	select {
	case <-time.After(1500 * time.Millisecond):
		// expected: dropped because noop translator cannot resolve
	case e := <-ch1.Chan():
		t.Fatalf("expected drop_undefined to drop trap, got %s", e.Entry.Line)
	}
}

func TestBuildLabelsStripsMeta(t *testing.T) {
	rec := traplib.Record{
		Source:   "10.0.0.1",
		TrapOID:  "1.3.6.1.6.3.1.1.5.1",
		TrapName: "1.3.6.1.6.3.1.1.5.1",
		Version:  "2c",
		PDUType:  "trap",
	}
	filtered := buildLabels(Arguments{Labels: map[string]string{"site": "hq"}}, rec, devicejoin.Identity{}, nil)
	require.Equal(t, "hq", string(filtered["site"]))
	require.NotContains(t, filtered, "__snmptrap_source")
	require.NotContains(t, filtered, "__snmptrap_oid")
}

func TestStampJoinPrimaryAndAlias(t *testing.T) {
	idx := devicejoin.NewIndex([]discovery.Target{
		discovery.NewTargetFromMap(map[string]string{
			"address":      "10.0.0.2",
			"device_name":  "spine1",
			"snmp_group":   "hq",
			"snmp_aliases": "10.0.0.10",
		}),
	})
	reg := prometheus.NewRegistry()
	m := newMetrics(reg)

	rec := traplib.Record{Source: "10.0.0.10"}
	id := stampJoin(&rec, idx, m)
	require.Equal(t, "spine1", rec.DeviceName)
	require.Equal(t, "hq", id.Group)

	rec2 := traplib.Record{Source: "8.8.8.8", AgentAddress: "10.0.0.2"}
	id = stampJoin(&rec2, idx, m)
	require.Equal(t, "spine1", rec2.DeviceName)

	rec3 := traplib.Record{Source: "1.2.3.4"}
	id = stampJoin(&rec3, idx, m)
	require.Empty(t, rec3.DeviceName)
	require.Empty(t, id.DeviceName)

	rec4 := traplib.Record{Source: "10.0.0.2"}
	stampJoin(&rec4, devicejoin.NewIndex(nil), m)
	require.Empty(t, rec4.DeviceName)

	mfs, err := reg.Gather()
	require.NoError(t, err)
	var joined, unjoined float64
	for _, mf := range mfs {
		switch mf.GetName() {
		case "loki_source_snmptrap_joined_total":
			joined = mf.GetMetric()[0].GetCounter().GetValue()
		case "loki_source_snmptrap_unjoined_total":
			unjoined = mf.GetMetric()[0].GetCounter().GetValue()
		}
	}
	require.Equal(t, 2.0, joined)
	require.Equal(t, 1.0, unjoined)
}

func TestBuildLabelsKeepsJoinIdentity(t *testing.T) {
	rec := traplib.Record{
		Source:     "10.0.0.10",
		DeviceName: "spine1",
		TrapOID:    "1.3.6.1.6.3.1.1.5.1",
		Version:    "2c",
		PDUType:    "trap",
	}
	filtered := buildLabels(Arguments{}, rec, devicejoin.Identity{Group: "hq"}, nil)
	require.Equal(t, "spine1", string(filtered["device_name"]))
	require.Equal(t, "hq", string(filtered["snmp_group"]))
}

func TestListenConfigChanged(t *testing.T) {
	base := Arguments{ListenAddress: "0.0.0.0:1620", Communities: []string{"public"}}
	same := base
	same.Targets = []discovery.Target{discovery.NewTargetFromMap(map[string]string{"address": "10.0.0.1"})}
	same.Labels = map[string]string{"job": "traps"}
	require.False(t, listenConfigChanged(base, same))

	moved := base
	moved.ListenAddress = "0.0.0.0:11620"
	require.True(t, listenConfigChanged(base, moved))

	comms := base
	comms.Communities = []string{"lab"}
	require.True(t, listenConfigChanged(base, comms))
}

func TestUpdateTargetsDoesNotRestartListener(t *testing.T) {
	opts := component.Options{
		Logger:        logging.NewSlogNop(),
		Registerer:    prometheus.NewRegistry(),
		OnStateChange: func(e component.Exports) {},
	}
	ch1 := loki.NewLogsReceiver()
	addr := componenttest.GetFreeAddr(t)
	args := Arguments{
		ListenAddress: addr,
		ForwardTo:     []loki.LogsReceiver{ch1},
	}
	c, err := New(opts, args)
	require.NoError(t, err)
	first := c.listener
	require.NotNil(t, first)

	args.Targets = []discovery.Target{
		discovery.NewTargetFromMap(map[string]string{
			"address":     "10.0.0.2",
			"device_name": "spine1",
		}),
	}
	require.NoError(t, c.Update(args))
	require.Same(t, first, c.listener)
	require.Equal(t, 1, c.join.Len())
}
