package snmptrap

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/grafana/alloy/internal/component"
	"github.com/grafana/alloy/internal/component/common/devicejoin"
	"github.com/grafana/alloy/internal/component/discovery"
	"github.com/grafana/alloy/internal/component/otelcol"
	otelcolConfig "github.com/grafana/alloy/internal/component/otelcol/config"
	"github.com/grafana/alloy/internal/component/otelcol/receiver"
	"github.com/grafana/alloy/internal/featuregate"
	"github.com/grafana/alloy/internal/snmppaths"
	traplib "github.com/grafana/alloy/internal/snmptrap"
	"github.com/grafana/alloy/syntax"
	"github.com/grafana/alloy/syntax/alloytypes"
	collectorComponent "go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/pipeline"
)

func init() {
	component.Register(component.Registration{
		Name:      "otelcol.receiver.snmptrap",
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

// Arguments configure otelcol.receiver.snmptrap.
type Arguments struct {
	ListenAddress    string            `alloy:"listen_address,attr,optional"`
	Communities      []string          `alloy:"communities,attr,optional"`
	IncludeCommunity bool              `alloy:"include_community,attr,optional"`
	DropUndefined    bool              `alloy:"drop_undefined,attr,optional"`
	MIBPaths         []string          `alloy:"mib_paths,attr,optional"`
	Attributes       map[string]string `alloy:"attributes,attr,optional"`
	Targets          []discovery.Target `alloy:"targets,attr,optional"`
	V3               *V3Arguments      `alloy:"v3,block,optional"`

	DebugMetrics otelcolConfig.DebugMetricsArguments `alloy:"debug_metrics,block,optional"`
	Output       *ConsumerArguments                  `alloy:"output,block"`
}

// V3Arguments is a single USM user for SNMPv3 traps/informs.
type V3Arguments struct {
	User          string            `alloy:"user,attr"`
	SecurityLevel string            `alloy:"security_level,attr,optional"`
	AuthProtocol  string            `alloy:"auth_protocol,attr,optional"`
	AuthPassword  alloytypes.Secret `alloy:"auth_password,attr,optional"`
	PrivProtocol  string            `alloy:"priv_protocol,attr,optional"`
	PrivPassword  alloytypes.Secret `alloy:"priv_password,attr,optional"`
}

// ConsumerArguments is the logs-only output block.
type ConsumerArguments struct {
	Logs []otelcol.Consumer `alloy:"logs,attr,optional"`
}

func (a *Arguments) SetToDefault() {
	a.ListenAddress = "0.0.0.0:1620"
	a.MIBPaths = []string{snmppaths.MIBDir}
	a.DebugMetrics.SetToDefault()
}

func (a *Arguments) Validate() error {
	if strings.TrimSpace(a.ListenAddress) == "" {
		return fmt.Errorf("listen_address must not be empty")
	}
	if a.V3 != nil && strings.TrimSpace(a.V3.User) == "" {
		return fmt.Errorf("v3.user is required when the v3 block is set")
	}
	if _, err := traplib.GoSNMPParams(a.listenConfig(), nil); err != nil {
		return err
	}
	return nil
}

func (a Arguments) Convert() (collectorComponent.Config, error) {
	return a.toConfig(nil, nil), nil
}

func (a Arguments) toConfig(join *atomic.Pointer[devicejoin.Index], metrics *recvMetrics) *Config {
	cfg := &Config{
		ListenAddress:    a.ListenAddress,
		Communities:      a.Communities,
		IncludeCommunity: a.IncludeCommunity,
		DropUndefined:    a.DropUndefined,
		MIBPaths:         a.MIBPaths,
		Attributes:       a.Attributes,
		Join:             join,
		Metrics:          metrics,
	}
	if a.V3 != nil {
		cfg.V3 = &traplib.V3Config{
			User:          a.V3.User,
			SecurityLevel: a.V3.SecurityLevel,
			AuthProtocol:  a.V3.AuthProtocol,
			AuthPassword:  string(a.V3.AuthPassword),
			PrivProtocol:  a.V3.PrivProtocol,
			PrivPassword:  string(a.V3.PrivPassword),
		}
	}
	return cfg
}

func (a Arguments) listenConfig() traplib.ListenConfig {
	lc := traplib.ListenConfig{
		ListenAddress:    a.ListenAddress,
		Communities:      a.Communities,
		IncludeCommunity: a.IncludeCommunity,
		DropUndefined:    a.DropUndefined,
		MIBPaths:         a.MIBPaths,
	}
	if a.V3 != nil {
		lc.V3 = &traplib.V3Config{
			User:          a.V3.User,
			SecurityLevel: a.V3.SecurityLevel,
			AuthProtocol:  a.V3.AuthProtocol,
			AuthPassword:  string(a.V3.AuthPassword),
			PrivProtocol:  a.V3.PrivProtocol,
			PrivPassword:  string(a.V3.PrivPassword),
		}
	}
	return lc
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
	if a.Output == nil {
		return &otelcol.ConsumerArguments{}
	}
	return &otelcol.ConsumerArguments{Logs: a.Output.Logs}
}

// Component wraps the Collector receiver so a discovery catalog can stamp
// device_name without restarting the UDP listener.
type Component struct {
	inner   *receiver.Receiver
	join    atomic.Pointer[devicejoin.Index]
	metrics *recvMetrics

	mut        sync.Mutex
	lastListen traplib.ListenConfig
}

var (
	_ component.Component       = (*Component)(nil)
	_ component.HealthComponent = (*Component)(nil)
	_ component.LiveDebugging   = (*Component)(nil)
	_ receiver.Arguments        = wrappingArgs{}
)

// New builds otelcol.receiver.snmptrap.
func New(opts component.Options, args Arguments) (*Component, error) {
	c := &Component{
		metrics: newRecvMetrics(opts.Registerer),
	}
	c.join.Store(devicejoin.NewIndex(args.Targets))
	inner, err := receiver.New(opts, NewFactory(), wrappingArgs{comp: c, Arguments: args})
	if err != nil {
		return nil, err
	}
	c.inner = inner
	c.lastListen = args.listenConfig()
	return c, nil
}

func (c *Component) Run(ctx context.Context) error {
	return c.inner.Run(ctx)
}

func (c *Component) Update(args component.Arguments) error {
	a := args.(Arguments)
	c.join.Store(devicejoin.NewIndex(a.Targets))

	c.mut.Lock()
	defer c.mut.Unlock()
	next := a.listenConfig()
	if !traplib.ListenChanged(c.lastListen, next) {
		return nil
	}
	c.lastListen = next
	return c.inner.Update(wrappingArgs{comp: c, Arguments: a})
}

func (c *Component) CurrentHealth() component.Health {
	return c.inner.CurrentHealth()
}

func (*Component) LiveDebugging() {}

type wrappingArgs struct {
	comp *Component
	Arguments
}

func (a wrappingArgs) Convert() (collectorComponent.Config, error) {
	var join *atomic.Pointer[devicejoin.Index]
	var metrics *recvMetrics
	if a.comp != nil {
		join = &a.comp.join
		metrics = a.comp.metrics
	}
	return a.Arguments.toConfig(join, metrics), nil
}
