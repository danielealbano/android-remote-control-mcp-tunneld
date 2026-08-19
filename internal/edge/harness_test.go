package edge

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/limit"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/phoneconn"
)

// scriptConn is a net.Conn that serves a fixed prefix (a peeked ClientHello) then blocks reads until
// closed, discards writes, and records closure + peer address.
type scriptConn struct {
	prefix   []byte
	off      int
	peer     string
	mu       sync.Mutex
	closed   bool
	closeCh  chan struct{}
	writes   []byte
	writesMu sync.Mutex
}

func newScriptConn(peer string, prefix []byte) *scriptConn {
	return &scriptConn{prefix: prefix, peer: peer, closeCh: make(chan struct{})}
}

func (c *scriptConn) Read(p []byte) (int, error) {
	if c.off < len(c.prefix) {
		n := copy(p, c.prefix[c.off:])
		c.off += n
		return n, nil
	}
	<-c.closeCh
	return 0, io.EOF
}

func (c *scriptConn) Write(p []byte) (int, error) {
	c.writesMu.Lock()
	c.writes = append(c.writes, p...)
	c.writesMu.Unlock()
	return len(p), nil
}

func (c *scriptConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	close(c.closeCh)
	return nil
}

func (c *scriptConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *scriptConn) LocalAddr() net.Addr              { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443} }
func (c *scriptConn) RemoteAddr() net.Addr             { return tcpAddr(c.peer) }
func (c *scriptConn) SetDeadline(time.Time) error      { return nil }
func (c *scriptConn) SetReadDeadline(time.Time) error  { return nil }
func (c *scriptConn) SetWriteDeadline(time.Time) error { return nil }

func tcpAddr(host string) net.Addr {
	ap, err := netip.ParseAddr(host)
	if err != nil {
		return &net.TCPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 51000}
	}
	return &net.TCPAddr{IP: ap.AsSlice(), Port: 51000}
}

// fakeRoute is one queued LookupRoute answer (for tests exercising the fresh-lookup retry).
type fakeRoute struct {
	nodeID, fp, connID string
	ok                 bool
	err                error
}

// fakeRouter fakes edge.Router. When `queue` is non-empty each LookupRoute consumes one entry;
// otherwise the static fields answer.
type fakeRouter struct {
	nodeID, fp, connID string
	ok                 bool
	err                error
	nodeAdv            string
	nodeOK             bool

	mu      sync.Mutex
	queue   []fakeRoute
	lookups int
}

func (r *fakeRouter) LookupRoute(context.Context, string) (string, string, string, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lookups++
	if len(r.queue) > 0 {
		q := r.queue[0]
		r.queue = r.queue[1:]
		return q.nodeID, q.fp, q.connID, q.ok, q.err
	}
	return r.nodeID, r.fp, r.connID, r.ok, r.err
}
func (r *fakeRouter) LookupNode(context.Context, string) (string, bool, error) {
	return r.nodeAdv, r.nodeOK, nil
}

// fakeLocal fakes edge.LocalDialer. When `errQueue` is non-empty each OpenStream consumes one entry (a
// nil entry means success, returning ds); otherwise the static ds/err answer.
type fakeLocal struct {
	has, owns bool
	ds        phoneconn.DataStream
	err       error
	opened    int
	mu        sync.Mutex
	errQueue  []error
}

func (l *fakeLocal) HasConn(string) bool          { return l.has }
func (l *fakeLocal) OwnsConn(string, string) bool { return l.owns }
func (l *fakeLocal) OpenStream(context.Context, string, string) (phoneconn.DataStream, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.opened++
	if len(l.errQueue) > 0 {
		e := l.errQueue[0]
		l.errQueue = l.errQueue[1:]
		if e != nil {
			return nil, e
		}
		return l.ds, nil
	}
	return l.ds, l.err
}

// fakeMesh fakes edge.MeshDialer. When `errQueue` is non-empty each OpenStream consumes one entry (a
// nil entry means success); otherwise the static rwc/err answer.
type fakeMesh struct {
	rwc      io.ReadWriteCloser
	err      error
	opened   int
	mu       sync.Mutex
	errQueue []error
}

func (m *fakeMesh) OpenStream(context.Context, string, string, string, string) (io.ReadWriteCloser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.opened++
	if len(m.errQueue) > 0 {
		e := m.errQueue[0]
		m.errQueue = m.errQueue[1:]
		if e != nil {
			return nil, e
		}
		return m.rwc, nil
	}
	return m.rwc, m.err
}

// pipeStream is an in-memory io.ReadWriteCloser backed by a byte source and a sink.
type pipeStream struct {
	r      io.Reader
	w      io.Writer
	closed chan struct{}
	once   sync.Once
}

func (p *pipeStream) Read(b []byte) (int, error)  { return p.r.Read(b) }
func (p *pipeStream) Write(b []byte) (int, error) { return p.w.Write(b) }
func (p *pipeStream) Close() error {
	p.once.Do(func() { close(p.closed) })
	return nil
}

// recRecorder captures edge.Recorder calls.
type recRecorder struct {
	mu       sync.Mutex
	rejects  []string
	quota    []string
	opens    int
	closes   int
	sOpen    int
	sClose   int
	bytesSum int64
}

func (r *recRecorder) Reject(reason, _, _ string) {
	r.mu.Lock()
	r.rejects = append(r.rejects, reason)
	r.mu.Unlock()
}
func (r *recRecorder) Bytes(_, _ string, n int64) { r.mu.Lock(); r.bytesSum += n; r.mu.Unlock() }
func (r *recRecorder) PublicConnOpen()            { r.mu.Lock(); r.opens++; r.mu.Unlock() }
func (r *recRecorder) PublicConnClose(string)     { r.mu.Lock(); r.closes++; r.mu.Unlock() }
func (r *recRecorder) StreamOpen()                { r.mu.Lock(); r.sOpen++; r.mu.Unlock() }
func (r *recRecorder) StreamClose()               { r.mu.Lock(); r.sClose++; r.mu.Unlock() }
func (r *recRecorder) QuotaExhausted(_, w string) {
	r.mu.Lock()
	r.quota = append(r.quota, w)
	r.mu.Unlock()
}

func (r *recRecorder) rejectReasons() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := append([]string(nil), r.rejects...)
	return out
}

// fakeSink captures PublicEvent connection-log writes.
type fakeSink struct {
	mu     sync.Mutex
	events []PublicEvent
}

func (s *fakeSink) PutConnLogPublic(_ context.Context, ev PublicEvent) {
	s.mu.Lock()
	s.events = append(s.events, ev)
	s.mu.Unlock()
}

// testEdge builds an Edge wired to fakes + a miniredis-backed limiter.
type testEdge struct {
	e     *Edge
	rec   *recRecorder
	sink  *fakeSink
	rtr   *fakeRouter
	local *fakeLocal
	mesh  *fakeMesh
}

func newTestEdge(t *testing.T, cfg Config, banIP func(netip.Addr) bool, banTun func(string, string) bool) *testEdge {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	lim := limit.NewLimiter(rdb, 1<<30, 1<<40, 1<<40, time.Hour) // generous caps unless a test overrides via keys

	rec := &recRecorder{}
	sink := &fakeSink{}
	rtr := &fakeRouter{}
	local := &fakeLocal{}
	mesh := &fakeMesh{}
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
	e := New(cfg, rdb, banIP, banTun, rec, rtr, local, mesh, lim, sink, addr)
	return &testEdge{e: e, rec: rec, sink: sink, rtr: rtr, local: local, mesh: mesh}
}

func containsStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
