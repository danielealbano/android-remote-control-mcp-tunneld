package edge

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/limit"
)

// Router resolves a tunnel name to its owner + fingerprint + connID.
type Router interface {
	LookupRoute(ctx context.Context, name string) (nodeID, fingerprint, connID string, ok bool, err error)
}

type DialBackWaiter interface {
	Await(ctx context.Context, token, tunnel string, open func(context.Context) error) (net.Conn, error)
}

type Opener interface {
	Open(ctx context.Context, nodeID, name, connID, token string) error
}

// StreamLimiter is the data-plane limiting surface the edge depends on. It is defined at the consumer
// (Go convention) so tests can substitute a fake; *limit.Limiter is the production implementation.
type StreamLimiter interface {
	AcquireStream(ctx context.Context, name, member string, maxN int) (bool, error)
	ReleaseStream(ctx context.Context, name, member string) error
	Charge(ctx context.Context, name, member, dir string, nr int64) (action limit.ChargeAction, wait time.Duration, window string, err error)
	TrafficExhausted(ctx context.Context, name string) (dayOver, weekOver bool, err error)
	Allow(ctx context.Context, scope string, ip netip.Addr, limit int, window time.Duration) (bool, time.Duration, error)
}

var _ StreamLimiter = (*limit.Limiter)(nil)

// Recorder is the metrics surface the edge needs.
type Recorder interface {
	Reject(reason, tunnelName, clientIP string)
	Bytes(tunnelName, direction string, n int64)
	PublicConnOpen()
	PublicConnClose(reason string)
	StreamOpen()
	StreamClose()
	QuotaExhausted(tunnelName, window string)
}

type ACMEChallenges interface {
	TLSALPNCertificate(ctx context.Context, domain string) (*tls.Certificate, bool, error)
}

// Config wires the Edge.
type Config struct {
	EnrollHost   string
	ControlHost  string
	TunnelDomain string // the tunnel base domain; a public SNI is <name>.<TunnelDomain>
	MaxClients   int
	ConnRate     int
	Concurrent   int

	HandshakeTimeout time.Duration
	DialBackTimeout  time.Duration
	IdleTimeout      time.Duration
	MinRate          int64
	MinGrace         time.Duration
	EvictIdle        time.Duration
	ProtectRate      int64

	Logger *slog.Logger
}

// Edge is the raw :443 public edge.
type Edge struct {
	cfg       Config
	ban       func(netip.Addr) bool
	banTun    func(name, fingerprint string) bool
	rec       Recorder
	router    Router
	dialBacks DialBackWaiter
	opener    Opener
	lim       StreamLimiter
	logs      PhoneEventSink
	chal      ACMEChallenges

	enrollLn  *chanListener
	controlLn *chanListener

	clients atomic.Int64
	now     func() time.Time

	wg sync.WaitGroup

	smu     sync.Mutex
	streams map[*activeStream]struct{}
}

// Wait blocks until every in-flight public-connection handler has returned or ctx expires (server
// drain: end events must be enqueued before the conn-log queue is flushed).
func (e *Edge) Wait(ctx context.Context) {
	done := make(chan struct{})
	go func() { e.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		e.cfg.Logger.Warn("drain deadline reached before every public handler returned", "err", ctx.Err())
	}
}

func closeLogged(logger *slog.Logger, what string, c io.Closer) {
	if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		logger.Debug("close failed", "what", what, "err", err)
	}
}

// PhoneEventSink writes public connection-log events (kept minimal to avoid an import cycle; server.Run
// passes the store).
type PhoneEventSink interface {
	PutConnLogPublic(ctx context.Context, ev PublicEvent)
}

// PublicEvent is the public connection-log event the edge emits.
type PublicEvent struct {
	Conn, Tunnel, Event, CloseReason string
	SrcIP                            string
	SrcPort                          int
	SNI, ALPN, TLSVersion, JA4       string
	StartedAt, EndedAt               time.Time
	BytesIn, BytesOut                int64
}

// New builds the Edge. enrollLn/controlLn are the reserved-SNI listeners the http servers accept from.
func New(cfg Config, ban func(netip.Addr) bool, banTun func(string, string) bool,
	rec Recorder, r Router, dialBacks DialBackWaiter, opener Opener, lim StreamLimiter, logs PhoneEventSink,
	chal ACMEChallenges, addr net.Addr) *Edge {
	return &Edge{
		cfg: cfg, ban: ban, banTun: banTun, rec: rec, router: r, dialBacks: dialBacks, opener: opener,
		lim: lim, logs: logs, chal: chal,
		enrollLn: newChanListener(addr, cfg.Logger), controlLn: newChanListener(addr, cfg.Logger), now: time.Now,
	}
}

// EnrollListener / ControlListener are the reserved-SNI listeners for the enroll + control HTTP servers.
func (e *Edge) EnrollListener() net.Listener  { return e.enrollLn }
func (e *Edge) ControlListener() net.Listener { return e.controlLn }

// Serve runs the accept loop on ln until ctx is done.
func (e *Edge) Serve(ctx context.Context, ln net.Listener) {
	go func() {
		<-ctx.Done()
		closeLogged(e.cfg.Logger, "edge listener", ln)
		closeLogged(e.cfg.Logger, "enroll listener", e.enrollLn)
		closeLogged(e.cfg.Logger, "control listener", e.controlLn)
	}()
	e.acceptLoop(ctx, ln)
}

// connRate enforces the per-IP TCP connection rate at accept.
func (e *Edge) connRate(ctx context.Context, ip netip.Addr) bool {
	ok, _, err := e.lim.Allow(ctx, "conn-rate", ip, e.cfg.ConnRate, time.Second)
	if err != nil {
		e.cfg.Logger.Debug("conn-rate check failed (allowing)", "ip", ip, "err", err)
		return true // fail-open on a control-plane error (never a hard outage)
	}
	return ok
}
