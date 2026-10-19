package phoneconn

import (
	"context"
	"errors"
	"fmt"
	"hash/crc32"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/router"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/wire"
)

// Router is the consumer-side routing surface phoneconn needs (BindRoute + owner-conditional
// heartbeat/unbind + self-heal). BindRoute returns router.ErrConnIDCollision when the connID collides
// with the current owner, so register re-mints and retries.
type Router interface {
	BindRoute(ctx context.Context, name, nodeID, connID string) error
	Heartbeat(ctx context.Context, name, connID string) (router.HeartbeatResult, error)
	Unbind(ctx context.Context, name, connID string) error
	BindRouteIfAbsentOrOwner(ctx context.Context, name, nodeID, connID string) (router.SelfHealResult, error)
}

// ConnLogStore is the connection-event log surface.
type ConnLogStore = store.ConnLogStore

// Recorder is the metrics surface phoneconn needs.
type Recorder interface {
	PhoneConnOpen()
	PhoneConnClose(reason string)
}

type ConnClosedHook interface {
	PhoneConnClosed(ctx context.Context, name, connID, reason string)
}

// conn is one live phone control connection.
type conn struct {
	name         string
	keyFP        string // identity-KEY fingerprint (correlates conn-log events with the registry)
	certSerial   string // identity-cert serial (hex, forensics)
	connID       string
	sessionStart time.Time
	meta         ConnMeta
	notAfter     time.Time     // identity-cert expiry (the conn is closed cert-expired once past it)
	hbDone       chan struct{} // closed by heartbeatLoop on exit (teardown waits on it before unbinding)

	send     chan []byte // control frames to write to the phone (control-stream response body)
	cancel   context.CancelFunc
	lastPong atomic.Int64 // unix nanos of the last PONG received (liveness)

	mu     sync.Mutex
	closed bool
	reason string
}

// teardownTimeout bounds the best-effort unbind + end-event writes on connection teardown (they run on
// context.Background — a hung control plane or store must never pin a teardown goroutine).
const teardownTimeout = 10 * time.Second

// Manager tracks live phone control connections, binds routes, writes conn-log events, and drives
// eviction.
type Manager struct {
	router    Router
	logs      ConnLogStore
	rec       Recorder
	closed    ConnClosedHook
	logger    *slog.Logger
	nodeID    string
	nodeHost  string
	nodeStart string
	routeTTL  time.Duration

	mu    sync.RWMutex
	conns map[string]*conn // name → conn

	bindMu [64]sync.Mutex // striped per-name locks serializing BindRoute + the local-map insert

	now func() time.Time
}

// bindLock returns the striped per-name mutex serializing BindRoute + the local-map insert, so a
// concurrent same-name bind can never leave the Valkey owner different from the local winner.
func (m *Manager) bindLock(name string) *sync.Mutex {
	return &m.bindMu[crc32.ChecksumIEEE([]byte(name))%uint32(len(m.bindMu))]
}

// Config wires the Manager.
type Config struct {
	Router    Router
	Logs      ConnLogStore
	Recorder  Recorder
	Closed    ConnClosedHook
	Logger    *slog.Logger
	NodeID    string
	NodeHost  string
	NodeStart string // ns process-start timestamp (RFC3339Nano)
	RouteTTL  time.Duration
}

// NewManager builds the Manager.
func NewManager(cfg Config) *Manager {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{
		router: cfg.Router, logs: cfg.Logs, rec: cfg.Recorder, closed: cfg.Closed, logger: logger,
		nodeID: cfg.NodeID, nodeHost: cfg.NodeHost, nodeStart: cfg.NodeStart, routeTTL: cfg.RouteTTL,
		conns: map[string]*conn{}, now: time.Now,
	}
}

// Lookup returns the live connection for a tunnel name, if any.
func (m *Manager) lookup(name string) (*conn, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.conns[name]
	return c, ok
}

// HasConn reports whether this node holds a live phone connection for name.
func (m *Manager) HasConn(name string) bool {
	c, ok := m.lookup(name)
	return ok && !c.isClosed()
}

// register binds the route, writes the phone start event, and records the connection. Returns the conn
// and a teardown func to defer.
func (m *Manager) register(ctx context.Context, c *conn) (func(), error) {
	// Serialize BindRoute + the local-map insert per name: a concurrent same-name bind must never leave
	// the Valkey owner different from the local winner.
	l := m.bindLock(c.name)
	l.Lock()
	defer l.Unlock()

	for attempt := 0; ; attempt++ {
		err := m.router.BindRoute(ctx, c.name, m.nodeID, c.connID)
		if err == nil {
			break
		}
		if !errors.Is(err, router.ErrConnIDCollision) || attempt >= 2 {
			return nil, err
		}
		c.connID = mustConnID() // collision with the previous conn's id — re-mint and retry
	}
	m.mu.Lock()
	// Supersede any existing local conn for the same name.
	if old := m.conns[c.name]; old != nil {
		old.close("phone-close")
	}
	m.conns[c.name] = c
	m.mu.Unlock()

	m.rec.PhoneConnOpen()
	m.writeEvent(ctx, c, "start", "")

	teardown := func() {
		c.close("phone-close") // cancel the conn ctx FIRST: no further heartbeat/self-heal can run
		<-c.hbDone             // wait for the heartbeat loop (incl. an in-flight self-heal) to exit
		m.mu.Lock()
		if m.conns[c.name] == c {
			delete(m.conns, c.name)
		}
		m.mu.Unlock()
		// Bounded: a hung control plane / store must not pin the teardown (the route also TTL-expires).
		tctx, cancel := context.WithTimeout(context.Background(), teardownTimeout)
		defer cancel()
		if err := m.router.Unbind(tctx, c.name, c.connID); err != nil { // owner-conditional
			m.logger.Warn("route unbind failed (route expires by TTL)", "tunnel", c.name, "err", err)
		}
		m.writeEvent(tctx, c, "end", c.closeReason())
		m.rec.PhoneConnClose(c.closeReason())
		m.closed.PhoneConnClosed(tctx, c.name, c.connID, c.closeReason())
	}
	return teardown, nil
}

// heartbeatLoop refreshes the route while the connection is owner, handling the three-state result:
// not-owner → close this superseded connection without unbinding; missing → epoch-preserving self-heal.
func (m *Manager) heartbeatLoop(ctx context.Context, c *conn) {
	defer close(c.hbDone)
	interval := m.routeTTL / 3
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			res, err := m.router.Heartbeat(ctx, c.name, c.connID)
			if err != nil {
				// Retrying next tick is fine for a blip, but a PERSISTENT failure (Valkey ACL/auth or a
				// partition to Valkey only) lets tunnel:{name} TTL-expire — public clients then get
				// no-route while the phone still believes it is connected. Surface it, don't swallow it.
				if ctx.Err() == nil {
					m.logger.Warn("route heartbeat failed (route expires by TTL if this persists)",
						"tunnel", c.name, "conn", c.connID, "err", err)
				}
				continue
			}
			switch res {
			case router.HeartbeatRefreshed:
			case router.HeartbeatNotOwner:
				c.close("phone-close") // superseded — do NOT unbind the new owner's route
				return
			case router.HeartbeatMissing:
				// Best-effort self-heal: a transient error/loss here is retried on the next heartbeat tick.
				if _, err := m.router.BindRouteIfAbsentOrOwner(ctx, c.name, m.nodeID, c.connID); err != nil && ctx.Err() == nil {
					m.logger.Warn("route self-heal failed (retried on the next heartbeat)",
						"tunnel", c.name, "conn", c.connID, "err", err)
				}
			}
		}
	}
}

func (m *Manager) SendOpen(ctx context.Context, name, connID string, open wire.OpenPayload) error {
	c, ok := m.lookup(name)
	if !ok || c.isClosed() || c.connID != connID {
		return ErrNoConn
	}
	frame, err := wire.EncodeControl(wire.CtrlOpen, open)
	if err != nil {
		return fmt.Errorf("encode OPEN frame for %s: %w", name, err)
	}
	select {
	case c.send <- frame:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("queue OPEN for %s: %w", name, ctx.Err())
	}
}

// CloseAll closes every live phone connection with the given close reason. Called at server drain so
// each /api/v1/control handler returns and its deferred teardown runs (owner-conditional route unbind + the
// durable end event) instead of the connections outliving Run and losing both.
func (m *Manager) CloseAll(reason string) {
	m.mu.RLock()
	victims := make([]*conn, 0, len(m.conns))
	for _, c := range m.conns {
		victims = append(victims, c)
	}
	m.mu.RUnlock()
	for _, c := range victims {
		c.close(reason)
	}
}

// EvictBanned closes every live connection whose name matches the ban predicate,
// recording ban-evict. Wired to the ban-reload hook in server.Run.
func (m *Manager) EvictBanned(match func(name string) bool) {
	m.mu.RLock()
	var victims []*conn
	for _, c := range m.conns {
		if match(c.name) {
			victims = append(victims, c)
		}
	}
	m.mu.RUnlock()
	for _, c := range victims {
		c.close("ban-evict")
	}
}

// Close closes the named tunnel's live phone control connection with the given close reason (recorded on
// the phone end event) and reports whether a live connection existed. Used by the admin terminate action.
func (m *Manager) Close(name, reason string) bool {
	c, ok := m.lookup(name)
	if !ok || c.isClosed() {
		return false
	}
	c.close(reason)
	return true
}

// ConnectedNames returns a snapshot of the tunnel names with a live phone connection on this node (the
// renewal watcher scans these to decide which certs to nudge).
func (m *Manager) ConnectedNames() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	names := make([]string, 0, len(m.conns))
	for name, c := range m.conns {
		if !c.isClosed() {
			names = append(names, name)
		}
	}
	return names
}

// SendRenewNudge enqueues a RENEW_NUDGE control frame carrying a fresh single-use challenge nonce,
// prompting the phone to renew via the mTLS POST /api/v1/issue endpoint. Returns false if no live connection
// exists or the send buffer is full (the next watcher tick retries).
func (m *Manager) SendRenewNudge(name, nonceHex, ariWindow string) bool {
	c, ok := m.lookup(name)
	if !ok || c.isClosed() {
		return false
	}
	frame, err := wire.EncodeControl(wire.CtrlRenewNudge, wire.RenewNudgePayload{Nonce: nonceHex, ARIWindow: ariWindow})
	if err != nil {
		m.logger.Warn("renew nudge encode failed", "tunnel", name, "err", err)
		return false
	}
	select {
	case c.send <- frame:
		return true
	default:
		return false
	}
}

func (m *Manager) writeEvent(ctx context.Context, c *conn, event, reason string) {
	if m.logs == nil {
		return
	}
	ev := store.Event{
		Schema: 1, Event: event, Conn: c.connID, Type: "phone", Tunnel: c.name,
		NodeHostname: m.nodeHost, NodeStart: m.nodeStart, TSStart: c.sessionStart,
		SrcIP: c.meta.SrcIP, SrcPort: c.meta.SrcPort,
		ALPN: c.meta.ALPN, TLSVersion: c.meta.TLSVersion, TLSFP: c.meta.JA4,
		IdentityKeyFP:      c.keyFP, // the KEY fingerprint — matches the registry's identity_key_fpr
		IdentityCertSerial: c.certSerial,
	}
	if event == "end" {
		ev.TSEnd = m.now().UTC()
		ev.DurationMS = ev.TSEnd.Sub(c.sessionStart).Milliseconds()
		ev.CloseReason = reason
	}
	if err := m.logs.PutConnLog(ctx, ev); err != nil {
		m.logger.Warn("phone conn-log write failed", "tunnel", c.name, "event", event, "err", err)
	}
}

func (c *conn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *conn) close(reason string) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.reason = reason
	c.mu.Unlock()
	if c.cancel != nil {
		c.cancel()
	}
}

func (c *conn) closeReason() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.reason == "" {
		return "phone-close"
	}
	return c.reason
}
