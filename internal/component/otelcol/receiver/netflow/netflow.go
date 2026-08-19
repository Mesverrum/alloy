package netflow

import (
	"fmt"

	"github.com/grafana/alloy/internal/component"
	"github.com/grafana/alloy/internal/component/discovery"
	"github.com/grafana/alloy/internal/component/otelcol"
	otelcolConfig "github.com/grafana/alloy/internal/component/otelcol/config"
	"github.com/grafana/alloy/internal/component/otelcol/receiver"
	"github.com/grafana/alloy/internal/featuregate"
	"github.com/grafana/alloy/syntax"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/netflowreceiver"
	collectorComponent "go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/pipeline"
)

func init() {
	component.Register(component.Registration{
		Name:      "otelcol.receiver.netflow",
		Stability: featuregate.StabilityExperimental,
		Args:      Arguments{},
		Build: func(opts component.Options, args component.Arguments) (component.Component, error) {
			return New(opts, args.(Arguments))
		},
	})
}

var (
	_ receiver.Arguments = (*Arguments)(nil)
	_ syntax.Defaulter   = (*Arguments)(nil)
	_ syntax.Validator   = (*Arguments)(nil)
)

// Arguments configures otelcol.receiver.netflow.
// The component wraps the upstream contrib netflow receiver (logs only —
// NetFlow/IPFIX or sFlow) and optionally joins flow.sampler_address to a
// discovery catalog without restarting the UDP listener.
type Arguments struct {
	// Scheme is the flow protocol: "netflow" (NetFlow v5/v9 + IPFIX) or "sflow".
	Scheme string `alloy:"scheme,attr,optional"`
	// Hostname is the address to bind. Empty listens on all interfaces.
	Hostname string `alloy:"hostname,attr,optional"`
	// Port is the UDP port to listen on.
	Port int `alloy:"port,attr,optional"`
	// Sockets is the number of UDP sockets.
	Sockets int `alloy:"sockets,attr,optional"`
	// Workers is the number of decode workers.
	Workers int `alloy:"workers,attr,optional"`
	// QueueSize is the inbound packet queue depth.
	QueueSize int `alloy:"queue_size,attr,optional"`
	// SendRaw forwards the undecoded goflow2 message as the log body
	// instead of parsed attributes.
	SendRaw bool `alloy:"send_raw,attr,optional"`

	// Targets is an optional discovery catalog (typically discovery.snmp.targets
	// or file-SD YAML with address / device_name / snmp_aliases). flow.sampler_address
	// is joined to device_name at receive time without restarting the UDP listener.
	Targets []discovery.Target `alloy:"targets,attr,optional"`

	// DebugMetrics configures component internal metrics. Optional.
	DebugMetrics otelcolConfig.DebugMetricsArguments `alloy:"debug_metrics,block,optional"`

	// Output configures where to send received data. Required.
	Output *ConsumerArguments `alloy:"output,block"`
}

func (a *Arguments) Validate() error {
	switch a.Scheme {
	case "netflow", "sflow":
	default:
		return fmt.Errorf("scheme must be netflow or sflow")
	}
	if a.Port <= 0 {
		return fmt.Errorf("port must be greater than 0")
	}
	if a.Sockets <= 0 {
		return fmt.Errorf("sockets must be greater than 0")
	}
	if a.Workers <= 0 {
		return fmt.Errorf("workers must be greater than 0")
	}
	return nil
}

func (a *Arguments) SetToDefault() {
	a.Scheme = "netflow"
	a.Port = 2055
	a.Sockets = 1
	a.Workers = 2
	a.QueueSize = 1000
	a.DebugMetrics.SetToDefault()
}

type ConsumerArguments struct {
	Logs []otelcol.Consumer `alloy:"logs,attr,optional"`
}

func (a Arguments) Convert() (collectorComponent.Config, error) {
	cfg := &netflowreceiver.Config{
		Scheme:    a.Scheme,
		Hostname:  a.Hostname,
		Port:      a.Port,
		Sockets:   a.Sockets,
		Workers:   a.Workers,
		QueueSize: a.QueueSize,
		SendRaw:   a.SendRaw,
	}
	return cfg, nil
}

func (a Arguments) DebugMetricsConfig() otelcolConfig.DebugMetricsArguments {
	return a.DebugMetrics
}

func (a Arguments) Exporters() map[pipeline.Signal]map[collectorComponent.ID]collectorComponent.Component {
	return nil
}

func (a Arguments) Extensions() map[collectorComponent.ID]collectorComponent.Component {
	return nil
}

func (a Arguments) NextConsumers() *otelcol.ConsumerArguments {
	return &otelcol.ConsumerArguments{
		Logs: a.Output.Logs,
	}
}
