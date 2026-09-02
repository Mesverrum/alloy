package netflow_test

import (
	"testing"

	"github.com/grafana/alloy/internal/component/otelcol/receiver/netflow"
	"github.com/grafana/alloy/syntax"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/netflowreceiver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig(t *testing.T) {
	alloyCfg := `
		scheme   = "sflow"
		hostname = "127.0.0.1"
		port     = 6343
		sockets  = 2
		workers  = 4
		queue_size = 500
		send_raw = true
		output {
		}
	`
	var args netflow.Arguments
	err := syntax.Unmarshal([]byte(alloyCfg), &args)
	require.NoError(t, err)
	require.NoError(t, args.Validate())

	comCfg, err := args.Convert()
	require.NoError(t, err)

	nfCfg, ok := comCfg.(*netflowreceiver.Config)
	require.True(t, ok)

	assert.Equal(t, "sflow", nfCfg.Scheme)
	assert.Equal(t, "127.0.0.1", nfCfg.Hostname)
	assert.Equal(t, 6343, nfCfg.Port)
	assert.Equal(t, 2, nfCfg.Sockets)
	assert.Equal(t, 4, nfCfg.Workers)
	assert.Equal(t, 500, nfCfg.QueueSize)
	assert.True(t, nfCfg.SendRaw)
}

func TestConfigDefault(t *testing.T) {
	args := netflow.Arguments{}
	args.SetToDefault()
	require.NoError(t, args.Validate())

	fCfg, err := args.Convert()
	require.NoError(t, err)
	cfg := netflowreceiver.NewFactory().CreateDefaultConfig()
	assert.Equal(t, cfg, fCfg)
}

func TestConfigInvalidScheme(t *testing.T) {
	args := netflow.Arguments{}
	args.SetToDefault()
	args.Scheme = "ipfix"
	assert.Error(t, args.Validate())
}

func TestConfigTargets(t *testing.T) {
	alloyCfg := `
		scheme = "netflow"
		port   = 2055
		targets = [
			{
				address     = "10.0.0.2",
				device_name = "spine1",
				snmp_group  = "hq",
			},
		]
		output {}
	`
	var args netflow.Arguments
	err := syntax.Unmarshal([]byte(alloyCfg), &args)
	require.NoError(t, err)
	require.Len(t, args.Targets, 1)
	dn, _ := args.Targets[0].Get("device_name")
	require.Equal(t, "spine1", dn)
}
