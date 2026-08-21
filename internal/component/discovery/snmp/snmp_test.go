package snmp

import (
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"

	"github.com/grafana/alloy/internal/component"
	"github.com/grafana/alloy/internal/service/livedebugging"
	"github.com/grafana/alloy/internal/snmpdiscovery"
	"github.com/grafana/alloy/internal/snmppaths"
	"github.com/grafana/alloy/syntax"
)

func TestAlloyConfig(t *testing.T) {
	const src = `
		snmp_config      = "/etc/alloy/snmp-network.yml"
		fingerprinters   = "/etc/alloy/fingerprinters.yml"
		refresh_interval = "30m"
		tier             = "hot"
		concurrency      = 16
		timeout          = "3s"
		retries          = 1
		port             = 1161
		ping             = false
		ping_timeout     = "200ms"
		misses           = 0
		state_path       = "/var/lib/alloy/snmp-discovery.state.json"
		allow_large               = true
		allow_duplicate_sysname   = true

		group {
			name   = "hq"
			cidrs  = ["172.20.20.0/24"]
			auths  = ["public_v2"]
			mode   = "sweep"
			port   = 161
		}

		override {
			address = "172.20.20.9"
			ignore  = true
		}
	`
	var args Arguments
	require.NoError(t, syntax.Unmarshal([]byte(src), &args))
	require.Equal(t, "/etc/alloy/snmp-network.yml", args.SnmpConfig)
	require.Equal(t, 30*time.Minute, args.RefreshInterval)
	require.Equal(t, "hot", args.Tier)
	require.Equal(t, 16, args.Concurrency)
	require.False(t, args.Ping, "explicit ping = false must survive SetToDefault")
	require.Equal(t, 200*time.Millisecond, args.PingTimeout)
	require.Equal(t, 0, args.Misses)
	require.True(t, args.AllowLarge)
	require.True(t, args.AllowDuplicateSysName)
	require.Len(t, args.Groups, 1)
	require.Equal(t, "hq", args.Groups[0].Name)
	require.Equal(t, []string{"public_v2"}, args.Groups[0].Auths)
	require.Len(t, args.Overrides, 1)
	require.True(t, args.Overrides[0].Ignore)
	require.NoError(t, args.Validate())
}

func TestAlloyConfigDefaultsPingTrue(t *testing.T) {
	const src = `
		group {
			name  = "hq"
			cidrs = ["10.0.0.0/30"]
			auths = ["public_v2"]
		}
	`
	var args Arguments
	require.NoError(t, syntax.Unmarshal([]byte(src), &args))
	require.True(t, args.Ping, "omitted ping must default true via SetToDefault")
	require.Equal(t, 15*time.Minute, args.RefreshInterval)
	require.Equal(t, "all", args.Tier)
	require.Equal(t, 8, args.Concurrency)
	require.Equal(t, 161, args.Port)
	require.Equal(t, snmppaths.NetworkConfigFile, args.SnmpConfig)
	require.Equal(t, snmppaths.FingerprintersFile, args.Fingerprinters)
	require.False(t, args.AllowDuplicateSysName, "omitted allow_duplicate_sysname must default false")
	require.NoError(t, args.Validate())
}

func TestArgumentsValidate(t *testing.T) {
	valid := func() Arguments {
		a := DefaultArguments
		a.SnmpConfig = "/etc/alloy/snmp.yml"
		a.Groups = []GroupArguments{{Name: "hq", Auths: []string{"public_v2"}, CIDRs: []string{"10.0.0.0/30"}}}
		return a
	}

	t.Run("ok", func(t *testing.T) {
		require.NoError(t, valid().Validate())
	})
	t.Run("missing snmp_config", func(t *testing.T) {
		a := valid()
		a.SnmpConfig = ""
		require.Error(t, a.Validate())
	})
	t.Run("missing groups", func(t *testing.T) {
		a := valid()
		a.Groups = nil
		require.Error(t, a.Validate())
	})
	t.Run("bad tier", func(t *testing.T) {
		a := valid()
		a.Tier = "nope"
		require.Error(t, a.Validate())
	})
	t.Run("concurrency", func(t *testing.T) {
		a := valid()
		a.Concurrency = 0
		require.EqualError(t, a.Validate(), "concurrency must be > 0")
	})
	t.Run("timeout", func(t *testing.T) {
		a := valid()
		a.Timeout = 0
		require.EqualError(t, a.Validate(), "timeout must be > 0")
	})
	t.Run("ping_timeout", func(t *testing.T) {
		a := valid()
		a.PingTimeout = 0
		require.EqualError(t, a.Validate(), "ping_timeout must be > 0")
	})
	t.Run("port", func(t *testing.T) {
		a := valid()
		a.Port = 0
		require.EqualError(t, a.Validate(), "port must be between 1 and 65535")
	})
	t.Run("retries", func(t *testing.T) {
		a := valid()
		a.Retries = -1
		require.EqualError(t, a.Validate(), "retries must be >= 0")
	})
	t.Run("misses", func(t *testing.T) {
		a := valid()
		a.Misses = -1
		require.EqualError(t, a.Validate(), "misses must be >= 0")
	})
	t.Run("refresh_interval", func(t *testing.T) {
		a := valid()
		a.RefreshInterval = 0
		require.Error(t, a.Validate())
	})
}

func TestExpandTiers(t *testing.T) {
	cat := []snmpdiscovery.AlloyTarget{{
		Name: "spine1", Address: "10.0.0.1", Module: "if_mib",
		ModuleCold: "system_mib", ModuleTopology: "lldp_mib",
		Auth: "public_v2", DeviceName: "spine1",
	}}
	all := expandTiers(cat, "all")
	require.Len(t, all, 3)
	hot := expandTiers(cat, "hot")
	require.Len(t, hot, 1)
	require.Equal(t, "hot", hot[0].tier)
	require.Equal(t, "if_mib", hot[0].target.Module)
}

func TestToDiscoveryTarget(t *testing.T) {
	tg := toDiscoveryTarget(snmpdiscovery.AlloyTarget{
		Name: "spine1-hot", Address: "10.0.0.1", Module: "if_mib",
		Auth: "public_v2", DeviceName: "spine1", SnmpGroup: "hq",
		SysObjectID: "1.3.6.1.4.1.6527",
		Aliases:     []string{"10.0.0.10"},
	}, "hot")
	addr, ok := tg.Get("address")
	require.True(t, ok)
	require.Equal(t, "10.0.0.1", addr)
	mod, _ := tg.Get("module")
	require.Equal(t, "if_mib", mod)
	tier, _ := tg.Get("snmp_tier")
	require.Equal(t, "hot", tier)
	group, _ := tg.Get("snmp_group")
	require.Equal(t, "hq", group)
	oid, _ := tg.Get("sysObjectID")
	require.Equal(t, "1.3.6.1.4.1.6527", oid)
	aliases, ok := tg.Get("snmp_aliases")
	require.True(t, ok)
	require.Equal(t, "10.0.0.10", aliases)
}

func TestDefaultRefresh(t *testing.T) {
	require.Equal(t, 15*time.Minute, DefaultArguments.RefreshInterval)
}

func TestScanOnceFailedScanSetsUnhealthy(t *testing.T) {
	reg := prometheus.NewRegistry()
	c, err := New(testOptions(t, reg, nil), validTestArgs())
	require.NoError(t, err)
	require.Equal(t, component.HealthTypeUnknown, c.CurrentHealth().Health)

	err = c.scanOnce()
	require.Error(t, err)
	h := c.CurrentHealth()
	require.Equal(t, component.HealthTypeUnhealthy, h.Health)
	require.Contains(t, h.Message, "scan failed")
	require.Equal(t, 1.0, counterValue(t, reg, "discovery_snmp_scans_total"))
	require.Equal(t, 1.0, counterValue(t, reg, "discovery_snmp_scan_failures_total"))
}

func TestScanOnceSkipsWhenLocked(t *testing.T) {
	reg := prometheus.NewRegistry()
	c, err := New(testOptions(t, reg, nil), validTestArgs())
	require.NoError(t, err)

	c.scanMu.Lock()
	t.Cleanup(c.scanMu.Unlock)

	require.NoError(t, c.scanOnce())
	require.Equal(t, 1.0, counterValue(t, reg, "discovery_snmp_scan_skipped_total"))
	require.Equal(t, component.HealthTypeUnknown, c.CurrentHealth().Health)
}

func TestNewRequiresLiveDebugging(t *testing.T) {
	_, err := New(component.Options{
		ID:            "discovery.snmp.test",
		Logger:        slog.Default(),
		Registerer:    prometheus.NewRegistry(),
		OnStateChange: func(e component.Exports) {},
		GetServiceData: func(name string) (any, error) {
			return nil, fmt.Errorf("service %q does not exist", name)
		},
	}, validTestArgs())
	require.Error(t, err)
}

func validTestArgs() Arguments {
	a := DefaultArguments
	a.SnmpConfig = "/no/such/snmp-network.yml"
	a.Fingerprinters = "/no/such/fingerprinters.yml"
	a.Ping = false
	a.Groups = []GroupArguments{{
		Name:  "hq",
		CIDRs: []string{"10.0.0.0/30"},
		Auths: []string{"public_v2"},
	}}
	return a
}

func testOptions(t *testing.T, reg prometheus.Registerer, onChange func(component.Exports)) component.Options {
	t.Helper()
	if onChange == nil {
		onChange = func(e component.Exports) {}
	}
	return component.Options{
		ID:            "discovery.snmp.test",
		Logger:        slog.Default(),
		Registerer:    reg,
		OnStateChange: onChange,
		GetServiceData: func(name string) (any, error) {
			if name == livedebugging.ServiceName {
				return livedebugging.NewLiveDebugging(), nil
			}
			return nil, fmt.Errorf("service %q does not exist", name)
		},
	}
}

func counterValue(t *testing.T, reg *prometheus.Registry, name string) float64 {
	t.Helper()
	mfs, err := reg.Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		require.NotEmpty(t, mf.GetMetric())
		if mf.GetType() == io_prometheus_client.MetricType_COUNTER {
			return mf.GetMetric()[0].GetCounter().GetValue()
		}
	}
	t.Fatalf("metric %s not found", name)
	return 0
}
