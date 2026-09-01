package snmptrap

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/grafana/alloy/internal/component/common/devicejoin"
	traplib "github.com/grafana/alloy/internal/snmptrap"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/receiver"
)

type snmpTrapReceiver struct {
	cfg    *Config
	next   consumer.Logs
	logger *slog.Logger

	listenMut sync.Mutex
	listener  *gosnmp.TrapListener
	tr        traplib.Translator

	queue chan plog.Logs
	wg    sync.WaitGroup
	stop  context.CancelFunc
}

func newReceiver(cfg *Config, _ receiver.Settings, next consumer.Logs) (*snmpTrapReceiver, error) {
	return &snmpTrapReceiver{
		cfg:    cfg,
		next:   next,
		logger: slog.Default(),
		queue:  make(chan plog.Logs, trapQueueCap),
	}, nil
}

func (r *snmpTrapReceiver) Start(ctx context.Context, _ component.Host) error {
	runCtx, cancel := context.WithCancel(context.Background())
	r.stop = cancel

	tr, err := traplib.NewGosmiTranslator(r.cfg.MIBPaths, r.logger)
	if err != nil {
		r.logger.Warn("snmptrap: gosmi translator unavailable, using numeric OIDs", "err", err)
		tr = traplib.NoopTranslator{}
	}
	r.tr = tr

	params, err := traplib.GoSNMPParams(r.listenConfig(), r.logger)
	if err != nil {
		cancel()
		return err
	}

	tl := gosnmp.NewTrapListener()
	tl.Params = params
	tl.OnNewTrap = func(packet *gosnmp.SnmpPacket, addr *net.UDPAddr) {
		r.handleTrap(packet, addr)
	}

	errCh := make(chan error, 1)
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		errCh <- tl.Listen(r.cfg.ListenAddress)
	}()

	select {
	case <-tl.Listening():
		r.logger.Info("listening for SNMP traps", "listen_address", r.cfg.ListenAddress)
	case err := <-errCh:
		r.wg.Wait()
		cancel()
		if err == nil {
			return context.Canceled
		}
		return err
	case <-ctx.Done():
		tl.Close()
		r.wg.Wait()
		cancel()
		return ctx.Err()
	}

	r.listenMut.Lock()
	r.listener = tl
	r.listenMut.Unlock()

	r.wg.Add(1)
	go r.drain(runCtx)
	return nil
}

func (r *snmpTrapReceiver) Shutdown(_ context.Context) error {
	if r.stop != nil {
		r.stop()
	}
	r.listenMut.Lock()
	if r.listener != nil {
		r.listener.Close()
		r.listener = nil
	}
	r.listenMut.Unlock()
	r.wg.Wait()
	return nil
}

func (r *snmpTrapReceiver) drain(ctx context.Context) {
	defer r.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case ld := <-r.queue:
			if r.next == nil {
				continue
			}
			if err := r.next.ConsumeLogs(ctx, ld); err != nil && r.metrics() != nil {
				r.metrics().errors.Inc()
			}
		}
	}
}

func (r *snmpTrapReceiver) handleTrap(packet *gosnmp.SnmpPacket, addr *net.UDPAddr) {
	start := time.Now()
	m := r.metrics()
	defer func() {
		if m != nil {
			m.handleDuration.Observe(time.Since(start).Seconds())
			m.noteQueue(len(r.queue))
		}
	}()

	if packet == nil {
		if m != nil {
			m.errors.Inc()
		}
		return
	}
	if m != nil {
		m.received.WithLabelValues(traplib.PDUKind(packet.PDUType)).Inc()
	}
	if !traplib.CommunityAllowed(r.cfg.Communities, packet.Community) {
		if m != nil {
			m.drop(reasonCommunity)
		}
		return
	}

	tr := r.tr
	if tr == nil {
		tr = traplib.NoopTranslator{}
	}
	rec := traplib.Decode(packet, addr, time.Now(), traplib.DecodeOptions{
		IncludeCommunity: r.cfg.IncludeCommunity,
		Translator:       tr,
	})
	if r.cfg.DropUndefined && !rec.Resolved() {
		if m != nil {
			m.drop(reasonUndefined)
		}
		return
	}

	stampJoin(&rec, r.joinIndex(), m)

	ld := traplib.LogsFromRecord(rec, r.cfg.Attributes)
	select {
	case r.queue <- ld:
		if m != nil {
			m.entries.Inc()
		}
	default:
		if m != nil {
			m.drop(reasonQueueFull)
		}
	}
}

func (r *snmpTrapReceiver) listenConfig() traplib.ListenConfig {
	return traplib.ListenConfig{
		ListenAddress:    r.cfg.ListenAddress,
		Communities:      r.cfg.Communities,
		IncludeCommunity: r.cfg.IncludeCommunity,
		DropUndefined:    r.cfg.DropUndefined,
		MIBPaths:         r.cfg.MIBPaths,
		V3:               r.cfg.V3,
	}
}

func (r *snmpTrapReceiver) metrics() *recvMetrics {
	if r.cfg == nil {
		return nil
	}
	return r.cfg.Metrics
}

func (r *snmpTrapReceiver) joinIndex() *devicejoin.Index {
	if r.cfg == nil || r.cfg.Join == nil {
		return nil
	}
	return r.cfg.Join.Load()
}

func stampJoin(rec *traplib.Record, join *devicejoin.Index, m *recvMetrics) {
	if rec == nil || join.Len() == 0 {
		return
	}
	id, ok := join.Lookup(rec.Source, rec.AgentAddress)
	if ok {
		rec.DeviceName = id.DeviceName
		rec.SnmpGroup = id.Group
		if m != nil && m.joined != nil {
			m.joined.Inc()
		}
		return
	}
	if m != nil && m.unjoined != nil {
		m.unjoined.Inc()
	}
}
