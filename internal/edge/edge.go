package edge

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/limit"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/phoneconn"
)

// Router resolves a tunnel name to its owner + fingerprint + connID + session-start epoch.
type Router interface {
	LookupRoute(ctx context.Context, name string) (nodeID, fingerprint, connID string, startedAt time.Time, ok bool, err error)
	LookupNode(ctx context.Context, nodeID string) (advertise string, ok bool, err error)
}

// LocalDialer opens a dial-back stream to a locally-held phone (phoneconn.Manager) and reports whether
// a phone is local.
type LocalDialer interface {
	OpenStream(ctx context.Context, name, streamID string) (phoneconn.DataStream, error)
	HasConn(name string) bool
	OwnsConn(name, connID string) bool
}

// MeshDialer opens a connID-checked mesh stream to the owning node.
type MeshDialer interface {
	OpenStream(ctx context.Context, peer, tunnel, connID, streamID string) (io.ReadWriteCloser, error)
}

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

// Config wires the Edge.
type Config struct {
	EnrollHost   string
	ControlHost  string
	TunnelDomain string // the tunnel base domain; a public SNI is <name>.<TunnelDomain>
	NodeID       string
	NodeHost     string
	NodeStart    string
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
}

// Edge is the raw :443 public edge.
type Edge struct {
	cfg    Config
	rdb    redis.UniversalClient
	ban    func(netip.Addr) bool
	banTun func(name, fingerprint string) bool
	rec    Recorder
	router Router
	local  LocalDialer
	mesh   MeshDialer
	lim    *limit.Limiter
	logs   PhoneEventSink

	enrollLn  *chanListener
	controlLn *chanListener

	clients atomic.Int64
	now     func() time.Time

	smu     sync.Mutex
	streams map[*activeStream]struct{}
}

var errNoOwner = errors.New("edge: no owner for tunnel")

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
func New(cfg Config, rdb redis.UniversalClient, ban func(netip.Addr) bool, banTun func(string, string) bool,
	rec Recorder, r Router, local LocalDialer, mesh MeshDialer, lim *limit.Limiter, logs PhoneEventSink,
	addr net.Addr) *Edge {
	return &Edge{
		cfg: cfg, rdb: rdb, ban: ban, banTun: banTun, rec: rec, router: r, local: local, mesh: mesh,
		lim: lim, logs: logs,
		enrollLn: newChanListener(addr), controlLn: newChanListener(addr), now: time.Now,
	}
}

// EnrollListener / ControlListener are the reserved-SNI listeners for the enroll + control HTTP servers.
func (e *Edge) EnrollListener() net.Listener  { return e.enrollLn }
func (e *Edge) ControlListener() net.Listener { return e.controlLn }

// Serve runs the accept loop on ln until ctx is done.
func (e *Edge) Serve(ctx context.Context, ln net.Listener) {
	go func() { <-ctx.Done(); _ = ln.Close(); _ = e.enrollLn.Close(); _ = e.controlLn.Close() }()
	e.acceptLoop(ctx, ln)
}

// connRate enforces the per-IP TCP connection rate at accept.
func (e *Edge) connRate(ctx context.Context, ip netip.Addr) bool {
	ok, _, err := limit.Allow(ctx, e.rdb, "conn-rate", ip, e.cfg.ConnRate, time.Second)
	if err != nil {
		return true // fail-open on a control-plane error (never a hard outage)
	}
	return ok
}
