package phoneconn

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/router"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/wire"
)

// Router is the consumer-side routing surface phoneconn needs (BindRoute + owner-conditional
// heartbeat/unbind + epoch-preserving self-heal).
type Router interface {
	BindRoute(ctx context.Context, name, nodeID, fingerprint, connID string, startedAt time.Time) error
	Heartbeat(ctx context.Context, name, connID string) (router.HeartbeatResult, error)
	Unbind(ctx context.Context, name, connID string) error
	BindRouteIfAbsentOrOwner(ctx context.Context, name, nodeID, fingerprint, connID string, startedAt time.Time) (router.SelfHealResult, error)
}

// ConnLogStore is the connection-event log surface.
type ConnLogStore = store.ConnLogStore

// Recorder is the metrics surface phoneconn needs.
type Recorder interface {
	PhoneConnOpen()
	PhoneConnClose(reason string)
}

// DataStream is a bidirectional splice handle to a dial-back data stream: Read pulls phone→client
// bytes, Write pushes client→phone bytes. Close tears the stream down.
type DataStream interface {
	io.ReadWriteCloser
}

// conn is one live phone control connection.
type conn struct {
	name         string
	fingerprint  string
	connID       string
	sessionStart time.Time
	meta         ConnMeta

	send   chan []byte // control frames to write to the phone (control-stream response body)
	cancel context.CancelFunc

	mu      sync.Mutex
	pending map[string]chan DataStream // streamID → dial-back waiter
	closed  bool
	reason  string
}

// Manager tracks live phone control connections, binds routes, writes conn-log events, and drives
// dial-back + eviction.
type Manager struct {
	router    Router
	logs      ConnLogStore
	rec       Recorder
	nodeID    string
	nodeHost  string
	nodeStart string
	routeTTL  time.Duration

	mu    sync.RWMutex
	conns map[string]*conn // name → conn

	now func() time.Time
}

// Config wires the Manager.
type Config struct {
	Router    Router
	Logs      ConnLogStore
	Recorder  Recorder
	NodeID    string
	NodeHost  string
	NodeStart string // ns process-start timestamp (RFC3339Nano)
	RouteTTL  time.Duration
}

// NewManager builds the Manager.
func NewManager(cfg Config) *Manager {
	return &Manager{
		router: cfg.Router, logs: cfg.Logs, rec: cfg.Recorder,
		nodeID: cfg.NodeID, nodeHost: cfg.NodeHost, nodeStart: cfg.NodeStart, routeTTL: cfg.RouteTTL,
		conns: map[string]*conn{}, now: time.Now,
	}
}

// Lookup returns the live connection for a tunnel name (fast path / eviction), if any.
func (m *Manager) lookup(name string) (*conn, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.conns[name]
	return c, ok
}

// OwnsConn reports whether this node holds the live phone connection for name with the given route
// connID (the mesh owner check before bridging).
func (m *Manager) OwnsConn(name, connID string) bool {
	c, ok := m.lookup(name)
	return ok && c.connID == connID && !c.isClosed()
}

// HasConn reports whether this node holds a live phone connection for name (the fast-path check).
func (m *Manager) HasConn(name string) bool {
	c, ok := m.lookup(name)
	return ok && !c.isClosed()
}

// register binds the route, writes the phone start event, and records the connection. Returns the conn
// and a teardown func to defer.
func (m *Manager) register(ctx context.Context, c *conn) (func(), error) {
	if err := m.router.BindRoute(ctx, c.name, m.nodeID, c.fingerprint, c.connID, c.sessionStart); err != nil {
		return nil, err
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
		m.mu.Lock()
		if m.conns[c.name] == c {
			delete(m.conns, c.name)
		}
		m.mu.Unlock()
		_ = m.router.Unbind(context.Background(), c.name, c.connID) // owner-conditional
		m.writeEvent(context.Background(), c, "end", c.closeReason())
		m.rec.PhoneConnClose(c.closeReason())
		c.close("phone-close")
	}
	return teardown, nil
}

// heartbeatLoop refreshes the route while the connection is owner, handling the three-state result:
// not-owner → close this superseded connection without unbinding; missing → epoch-preserving self-heal.
func (m *Manager) heartbeatLoop(ctx context.Context, c *conn) {
	ticker := time.NewTicker(m.routeTTL / 3)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			res, err := m.router.Heartbeat(ctx, c.name, c.connID)
			if err != nil {
				continue
			}
			switch res {
			case router.HeartbeatRefreshed:
			case router.HeartbeatNotOwner:
				c.close("phone-close") // superseded — do NOT unbind the new owner's route
				return
			case router.HeartbeatMissing:
				_, _ = m.router.BindRouteIfAbsentOrOwner(ctx, c.name, m.nodeID, c.fingerprint, c.connID, c.sessionStart)
			}
		}
	}
}

// OpenStream sends a dial-back OPEN{streamID} on the control stream and waits for the phone's data
// stream (correlated by streamID), returning a bidirectional splice handle. Used by the local bridge
// (US11) and the mesh handler (US9). Times out if the phone fails to dial back.
func (m *Manager) OpenStream(ctx context.Context, name, streamID string) (DataStream, error) {
	c, ok := m.lookup(name)
	if !ok {
		return nil, ErrNoConn
	}
	waiter := make(chan DataStream, 1)
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, ErrNoConn
	}
	c.pending[streamID] = waiter
	c.mu.Unlock()

	frame, _ := wire.EncodeControl(wire.CtrlOpen, wire.OpenPayload{StreamID: streamID})
	select {
	case c.send <- frame:
	case <-ctx.Done():
		c.dropPending(streamID)
		return nil, ctx.Err()
	}

	select {
	case ds := <-waiter:
		return ds, nil
	case <-ctx.Done():
		c.dropPending(streamID)
		return nil, ctx.Err()
	}
}

// deliverStream hands an arriving dial-back data stream to its waiter (called by the /data handler).
func (m *Manager) deliverStream(name, streamID string, ds DataStream) bool {
	c, ok := m.lookup(name)
	if !ok {
		return false
	}
	c.mu.Lock()
	w := c.pending[streamID]
	delete(c.pending, streamID)
	c.mu.Unlock()
	if w == nil {
		return false
	}
	w <- ds
	return true
}

// EvictBanned closes every live connection whose (name, fingerprint) matches the ban predicate,
// recording ban-evict. Wired to the ban-reload hook in server.Run.
func (m *Manager) EvictBanned(match func(name, fingerprint string) bool) {
	m.mu.RLock()
	var victims []*conn
	for _, c := range m.conns {
		if match(c.name, c.fingerprint) {
			victims = append(victims, c)
		}
	}
	m.mu.RUnlock()
	for _, c := range victims {
		c.close("ban-evict")
	}
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
// prompting the phone to renew via the mTLS POST /issue endpoint. Returns false if no live connection
// exists or the send buffer is full (the next watcher tick retries).
func (m *Manager) SendRenewNudge(name, nonceHex, ariWindow string) bool {
	c, ok := m.lookup(name)
	if !ok || c.isClosed() {
		return false
	}
	frame, err := wire.EncodeControl(wire.CtrlRenewNudge, wire.RenewNudgePayload{Nonce: nonceHex, ARIWindow: ariWindow})
	if err != nil {
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
		IdentityKeyFP: c.fingerprint,
	}
	if event == "end" {
		ev.TSEnd = m.now().UTC()
		ev.DurationMS = ev.TSEnd.Sub(c.sessionStart).Milliseconds()
		ev.CloseReason = reason
	}
	_ = m.logs.PutConnLog(ctx, ev)
}

func (c *conn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *conn) dropPending(streamID string) {
	c.mu.Lock()
	delete(c.pending, streamID)
	c.mu.Unlock()
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
