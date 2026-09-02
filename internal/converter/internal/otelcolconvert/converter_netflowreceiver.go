package otelcolconvert

import (
	"fmt"

	"github.com/grafana/alloy/internal/component/otelcol/receiver/netflow"
	"github.com/grafana/alloy/internal/converter/diag"
	"github.com/grafana/alloy/internal/converter/internal/common"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/netflowreceiver"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componentstatus"
)

func init() {
	converters = append(converters, netflowReceiverConverter{})
}

type netflowReceiverConverter struct{}

func (netflowReceiverConverter) Factory() component.Factory {
	return netflowreceiver.NewFactory()
}

func (netflowReceiverConverter) InputComponentName() string {
	return "otelcol.receiver.netflow"
}

func (netflowReceiverConverter) ConvertAndAppend(state *State, id componentstatus.InstanceID, cfg component.Config) diag.Diagnostics {
	var diags diag.Diagnostics

	label := state.AlloyComponentLabel()

	args := toOtelcolReceiverNetflow(cfg.(*netflowreceiver.Config))
	block := common.NewBlockWithOverride([]string{"otelcol", "receiver", "netflow"}, label, args)

	diags.Add(
		diag.SeverityLevelInfo,
		fmt.Sprintf("Converted %s into %s", StringifyInstanceID(id), StringifyBlock(block)),
	)

	state.Body().AppendBlock(block)
	return diags
}

func toOtelcolReceiverNetflow(cfg *netflowreceiver.Config) *netflow.Arguments {
	args := &netflow.Arguments{
		Scheme:       cfg.Scheme,
		Hostname:     cfg.Hostname,
		Port:         cfg.Port,
		Sockets:      cfg.Sockets,
		Workers:      cfg.Workers,
		QueueSize:    cfg.QueueSize,
		SendRaw:      cfg.SendRaw,
		DebugMetrics: common.DefaultValue[netflow.Arguments]().DebugMetrics,
	}

	return args
}
