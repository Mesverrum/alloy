package snmptrap

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/grafana/alloy/internal/component/common/devicejoin"
	traplib "github.com/grafana/alloy/internal/snmptrap"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver"
)

const typeStr = "snmptrap"

// Config is the OpenTelemetry Collector receiver config.
type Config struct {
	ListenAddress    string            `mapstructure:"listen_address"`
	Communities      []string          `mapstructure:"communities"`
	IncludeCommunity bool              `mapstructure:"include_community"`
	DropUndefined    bool              `mapstructure:"drop_undefined"`
	MIBPaths         []string          `mapstructure:"mib_paths"`
	Attributes       map[string]string `mapstructure:"attributes"`
	V3               *traplib.V3Config `mapstructure:"v3"`

	// Join and Metrics are Alloy-only; not River / mapstructure.
	Join    *atomic.Pointer[devicejoin.Index] `mapstructure:"-"`
	Metrics *recvMetrics                      `mapstructure:"-"`
}

var _ component.Config = (*Config)(nil)

// Validate implements xconfmap.Validator-style checks.
func (c *Config) Validate() error {
	if strings.TrimSpace(c.ListenAddress) == "" {
		return fmt.Errorf("listen_address must not be empty")
	}
	if c.V3 != nil && strings.TrimSpace(c.V3.User) == "" {
		return fmt.Errorf("v3.user is required when the v3 block is set")
	}
	return nil
}

func createDefaultConfig() component.Config {
	return &Config{
		ListenAddress: "0.0.0.0:1620",
	}
}

// NewFactory creates the Collector factory used by the Alloy wrapper.
func NewFactory() receiver.Factory {
	return receiver.NewFactory(
		component.MustNewType(typeStr),
		createDefaultConfig,
		receiver.WithLogs(createLogsReceiver, component.StabilityLevelDevelopment),
	)
}

func createLogsReceiver(
	_ context.Context,
	set receiver.Settings,
	cfg component.Config,
	next consumer.Logs,
) (receiver.Logs, error) {
	c, ok := cfg.(*Config)
	if !ok {
		return nil, fmt.Errorf("invalid config type %T", cfg)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return newReceiver(c, set, next)
}
