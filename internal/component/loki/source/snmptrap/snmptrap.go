// Package snmptrap implements loki.source.snmptrap — UDP SNMP trap/inform
// receiver that forwards structured JSON log entries.
package snmptrap

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/grafana/loki/pkg/push"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/relabel"

	"github.com/grafana/alloy/internal/component"
	"github.com/grafana/alloy/internal/component/common/devicejoin"
	"github.com/grafana/alloy/internal/component/common/loki"
	alloy_relabel "github.com/grafana/alloy/internal/component/common/relabel"
	"github.com/grafana/alloy/internal/component/discovery"
	"github.com/grafana/alloy/internal/featuregate"
	"github.com/grafana/alloy/internal/snmppaths"
	traplib "github.com/grafana/alloy/internal/snmptrap"
	"github.com/grafana/alloy/syntax/alloytypes"
)

func init() {
	component.Register(component.Registration{
		Name:      "loki.source.snmptrap",
		Stability: featuregate.StabilityExperimental,
		Args:      Arguments{},

		Build: func(opts component.Options, args component.Arguments) (component.Component, error) {
			return New(opts, args.(Arguments))
		},
	})
}

// Arguments configure loki.source.snmptrap.
type Arguments struct {
	ListenAddress    string              `alloy:"listen_address,attr,optional"`
	Communities      []string            `alloy:"communities,attr,optional"`
	IncludeCommunity bool                `alloy:"include_community,attr,optional"`
	DropUndefined    bool                `alloy:"drop_undefined,attr,optional"`
	MIBPaths         []string            `alloy:"mib_paths,attr,optional"`
	Labels           map[string]string   `alloy:"labels,attr,optional"`
	RelabelRules     alloy_relabel.Rules `alloy:"relabel_rules,attr,optional"`
	ForwardTo        []loki.LogsReceiver `alloy:"forward_to,attr"`
	// Targets is an optional discovery catalog (typically discovery.snmp.targets).
	// Source IP (and SNMPv1 agent address) is joined to device_name at receive time.
	Targets []discovery.Target `alloy:"targets,attr,optional"`
	V3      *V3Arguments       `alloy:"v3,block,optional"`
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

// DefaultArguments is the default listener config.
var DefaultArguments = Arguments{
	ListenAddress: "0.0.0.0:1620",
	MIBPaths:      []string{snmppaths.MIBDir},
}

// SetToDefault implements syntax.Defaulter.
func (args *Arguments) SetToDefault() {
	*args = DefaultArguments
}

// Validate implements syntax.Validator.
func (args Arguments) Validate() error {
	if strings.TrimSpace(args.ListenAddress) == "" {
		return fmt.Errorf("listen_address must not be empty")
	}
	if args.V3 != nil {
		if strings.TrimSpace(args.V3.User) == "" {
			return fmt.Errorf("v3.user is required when the v3 block is set")
		}
		if _, err := mapMsgFlags(args.V3.SecurityLevel); err != nil {
			return err
		}
		if _, err := mapAuthProtocol(args.V3.AuthProtocol); err != nil {
			return err
		}
		if _, err := mapPrivProtocol(args.V3.PrivProtocol); err != nil {
			return err
		}
	}
	return nil
}

// Component implements loki.source.snmptrap.
type Component struct {
	opts    component.Options
	metrics *Metrics
	handler loki.LogsReceiver
	fanout  *loki.Fanout

	// cfgMut guards receive-path state. Must not be held while waiting on the
	// UDP listener — OnNewTrap runs on the listen goroutine.
	cfgMut sync.RWMutex
	args   Arguments
	join   *devicejoin.Index
	tr     traplib.Translator
	rcs    []*relabel.Config

	listenMut sync.Mutex
	listener  *gosnmp.TrapListener
	wg        sync.WaitGroup
}

var _ component.Component = (*Component)(nil)

// New constructs the component and starts the first listener.
func New(o component.Options, args Arguments) (*Component, error) {
	c := &Component{
		opts:    o,
		metrics: newMetrics(o.Registerer),
		handler: loki.NewLogsReceiver(loki.WithChannel(make(chan loki.Entry, trapQueueCap))),
		fanout:  loki.NewFanout(args.ForwardTo),
	}
	if err := c.Update(args); err != nil {
		return nil, err
	}
	return c, nil
}

// Run implements component.Component.
func (c *Component) Run(ctx context.Context) error {
	defer func() {
		c.opts.Logger.Info("loki.source.snmptrap shutting down")
		loki.Drain(c.handler, c.fanout, loki.DefaultDrainTimeout, func() {
			c.stopListener()
		})
	}()
	loki.Consume(ctx, c.handler, c.fanout)
	return nil
}

// Update implements component.Component.
func (c *Component) Update(args component.Arguments) error {
	newArgs := args.(Arguments)

	c.listenMut.Lock()
	defer c.listenMut.Unlock()

	c.cfgMut.Lock()
	old := c.args
	c.args = newArgs
	c.join = devicejoin.NewIndex(newArgs.Targets)
	c.fanout.UpdateChildren(newArgs.ForwardTo)

	var rcs []*relabel.Config
	if len(newArgs.RelabelRules) > 0 {
		rcs = alloy_relabel.ComponentToPromRelabelConfigs(newArgs.RelabelRules)
	}
	c.rcs = rcs

	restart := c.listener == nil || listenConfigChanged(old, newArgs)
	if !restart {
		c.cfgMut.Unlock()
		return nil
	}

	tr, err := traplib.NewGosmiTranslator(newArgs.MIBPaths, c.opts.Logger)
	if err != nil {
		c.opts.Logger.Warn("snmptrap: gosmi translator unavailable, using numeric OIDs", "err", err)
		tr = traplib.NoopTranslator{}
	}
	c.tr = tr
	c.cfgMut.Unlock()

	c.stopListenerLocked()

	params, err := gosnmpParams(newArgs, c.opts.Logger)
	if err != nil {
		return err
	}

	tl := gosnmp.NewTrapListener()
	tl.Params = params
	tl.OnNewTrap = func(packet *gosnmp.SnmpPacket, addr *net.UDPAddr) {
		c.handleTrap(packet, addr)
	}

	errCh := make(chan error, 1)
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		errCh <- tl.Listen(newArgs.ListenAddress)
	}()

	select {
	case <-tl.Listening():
		c.opts.Logger.Info("listening for SNMP traps", "listen_address", newArgs.ListenAddress)
	case err := <-errCh:
		c.wg.Wait()
		if err == nil {
			return fmt.Errorf("snmptrap listener exited before becoming ready")
		}
		return fmt.Errorf("listen %s: %w", newArgs.ListenAddress, err)
	}

	c.listener = tl
	return nil
}

func listenConfigChanged(old, new Arguments) bool {
	if old.ListenAddress != new.ListenAddress {
		return true
	}
	if !slices.Equal(old.Communities, new.Communities) {
		return true
	}
	if !slices.Equal(old.MIBPaths, new.MIBPaths) {
		return true
	}
	return v3Changed(old.V3, new.V3)
}

func v3Changed(a, b *V3Arguments) bool {
	if a == nil && b == nil {
		return false
	}
	if a == nil || b == nil {
		return true
	}
	return a.User != b.User || a.SecurityLevel != b.SecurityLevel ||
		a.AuthProtocol != b.AuthProtocol || a.PrivProtocol != b.PrivProtocol ||
		string(a.AuthPassword) != string(b.AuthPassword) ||
		string(a.PrivPassword) != string(b.PrivPassword)
}

func (c *Component) stopListener() {
	c.listenMut.Lock()
	defer c.listenMut.Unlock()
	c.stopListenerLocked()
}

func (c *Component) stopListenerLocked() {
	if c.listener != nil {
		c.listener.Close()
		c.listener = nil
	}
	c.wg.Wait()
}

func (c *Component) handleTrap(packet *gosnmp.SnmpPacket, addr *net.UDPAddr) {
	start := time.Now()
	defer func() {
		c.metrics.handleDuration.Observe(time.Since(start).Seconds())
		c.metrics.noteQueue(len(c.handler.Chan()))
	}()

	c.cfgMut.RLock()
	args := c.args
	join := c.join
	tr := c.tr
	rcs := c.rcs
	c.cfgMut.RUnlock()
	if tr == nil {
		tr = traplib.NoopTranslator{}
	}

	if packet == nil {
		c.metrics.errors.Inc()
		return
	}
	c.metrics.received.WithLabelValues(trapPDULabel(packet.PDUType)).Inc()
	if !communityAllowed(args.Communities, packet.Community) {
		c.metrics.drop(reasonCommunity)
		return
	}

	rec := traplib.Decode(packet, addr, time.Now(), traplib.DecodeOptions{
		IncludeCommunity: args.IncludeCommunity,
		Translator:       tr,
	})
	if args.DropUndefined && !rec.Resolved() {
		c.metrics.drop(reasonUndefined)
		return
	}

	id := stampJoin(&rec, join, c.metrics)

	line, err := rec.MarshalJSONLine()
	if err != nil {
		c.opts.Logger.Warn("snmptrap: marshal failed", "err", err)
		c.metrics.errors.Inc()
		return
	}

	filtered := buildLabels(args, rec, id, rcs)
	entry := loki.NewEntry(filtered, push.Entry{
		Timestamp: rec.Time,
		Line:      string(line),
	})

	select {
	case c.handler.Chan() <- entry:
		c.metrics.entries.Inc()
	default:
		c.metrics.drop(reasonQueueFull)
	}
}

// stampJoin sets rec.DeviceName from the discovery catalog. Metrics increment
// only when a catalog is present.
func stampJoin(rec *traplib.Record, join *devicejoin.Index, m *Metrics) devicejoin.Identity {
	if rec == nil || join.Len() == 0 {
		return devicejoin.Identity{}
	}
	id, ok := join.Lookup(rec.Source, rec.AgentAddress)
	if ok {
		rec.DeviceName = id.DeviceName
		if m != nil && m.joined != nil {
			m.joined.Inc()
		}
		return id
	}
	if m != nil && m.unjoined != nil {
		m.unjoined.Inc()
	}
	return devicejoin.Identity{}
}

func communityAllowed(allow []string, got string) bool {
	if len(allow) == 0 {
		return true
	}
	for _, c := range allow {
		if c == got {
			return true
		}
	}
	return false
}

func buildLabels(args Arguments, rec traplib.Record, id devicejoin.Identity, rcs []*relabel.Config) model.LabelSet {
	lb := labels.NewBuilder(labels.EmptyLabels())
	for k, v := range args.Labels {
		lb.Set(k, v)
	}
	if rec.DeviceName != "" {
		lb.Set("device_name", rec.DeviceName)
	}
	if id.Group != "" {
		lb.Set("snmp_group", id.Group)
	}
	lb.Set("__snmptrap_source", rec.Source)
	lb.Set("__snmptrap_oid", rec.TrapOID)
	lb.Set("__snmptrap_name", rec.TrapName)
	lb.Set("__snmptrap_mib", rec.MIB)
	lb.Set("__snmptrap_version", rec.Version)
	lb.Set("__snmptrap_pdu", rec.PDUType)
	if rec.EngineID != "" {
		lb.Set("__snmptrap_engine_id", rec.EngineID)
	}
	if rec.ContextName != "" {
		lb.Set("__snmptrap_context", rec.ContextName)
	}
	if args.IncludeCommunity && rec.Community != "" {
		lb.Set("community", rec.Community)
	}

	processed := labels.EmptyLabels()
	if relabel.ProcessBuilder(lb, rcs...) {
		processed = lb.Labels()
	}

	filtered := make(model.LabelSet)
	processed.Range(func(lbl labels.Label) {
		if strings.HasPrefix(lbl.Name, "__") {
			return
		}
		filtered[model.LabelName(lbl.Name)] = model.LabelValue(lbl.Value)
	})
	return filtered
}

func gosnmpParams(args Arguments, log *slog.Logger) (*gosnmp.GoSNMP, error) {
	params := &gosnmp.GoSNMP{
		Port:               162,
		Transport:          "udp",
		Version:            gosnmp.Version2c,
		Timeout:            time.Second,
		Retries:            0,
		ExponentialTimeout: true,
		MaxOids:            60,
		Logger:             gosnmp.NewLogger(snmpLogger{log: log}),
	}
	if args.V3 == nil {
		return params, nil
	}

	params.Version = gosnmp.Version3
	params.SecurityModel = gosnmp.UserSecurityModel
	flags, err := mapMsgFlags(args.V3.SecurityLevel)
	if err != nil {
		return nil, err
	}
	params.MsgFlags = flags

	auth, err := mapAuthProtocol(args.V3.AuthProtocol)
	if err != nil {
		return nil, err
	}
	priv, err := mapPrivProtocol(args.V3.PrivProtocol)
	if err != nil {
		return nil, err
	}
	params.SecurityParameters = &gosnmp.UsmSecurityParameters{
		UserName:                 args.V3.User,
		AuthenticationProtocol:   auth,
		AuthenticationPassphrase: string(args.V3.AuthPassword),
		PrivacyProtocol:          priv,
		PrivacyPassphrase:        string(args.V3.PrivPassword),
	}
	return params, nil
}

func mapMsgFlags(level string) (gosnmp.SnmpV3MsgFlags, error) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "", "noauthnopriv":
		return gosnmp.NoAuthNoPriv, nil
	case "authnopriv":
		return gosnmp.AuthNoPriv, nil
	case "authpriv":
		return gosnmp.AuthPriv, nil
	default:
		return 0, unknownEnum("security_level", level)
	}
}

func mapAuthProtocol(p string) (gosnmp.SnmpV3AuthProtocol, error) {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "", "none", "noauth":
		return gosnmp.NoAuth, nil
	case "md5":
		return gosnmp.MD5, nil
	case "sha":
		return gosnmp.SHA, nil
	case "sha224":
		return gosnmp.SHA224, nil
	case "sha256":
		return gosnmp.SHA256, nil
	case "sha384":
		return gosnmp.SHA384, nil
	case "sha512":
		return gosnmp.SHA512, nil
	default:
		return 0, unknownEnum("auth_protocol", p)
	}
}

func mapPrivProtocol(p string) (gosnmp.SnmpV3PrivProtocol, error) {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "", "none", "nopriv":
		return gosnmp.NoPriv, nil
	case "des":
		return gosnmp.DES, nil
	case "aes":
		return gosnmp.AES, nil
	case "aes192":
		return gosnmp.AES192, nil
	case "aes192c":
		return gosnmp.AES192C, nil
	case "aes256":
		return gosnmp.AES256, nil
	case "aes256c":
		return gosnmp.AES256C, nil
	default:
		return 0, unknownEnum("priv_protocol", p)
	}
}

type snmpLogger struct {
	log *slog.Logger
}

func (s snmpLogger) Print(v ...interface{}) {
	if s.log == nil {
		return
	}
	s.log.Debug(fmt.Sprint(v...))
}

func (s snmpLogger) Printf(format string, v ...interface{}) {
	if s.log == nil {
		return
	}
	s.log.Debug(fmt.Sprintf(format, v...))
}
