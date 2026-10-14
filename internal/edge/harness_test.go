package edge

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/limit"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
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

func (r *fakeRouter) set(nodeID, fp, connID string, ok bool, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nodeID, r.fp, r.connID, r.ok, r.err = nodeID, fp, connID, ok, err
}

type fakeDialBacks struct {
	mu      sync.Mutex
	tokens  []string
	tunnels []string
	err     error
	never   bool
	phones  []net.Conn
}

func (f *fakeDialBacks) Await(ctx context.Context, token, tunnel string, open func(context.Context) error) (net.Conn, error) {
	f.mu.Lock()
	f.tokens = append(f.tokens, token)
	f.tunnels = append(f.tunnels, tunnel)
	err, never := f.err, f.never
	f.mu.Unlock()
	if oerr := open(ctx); oerr != nil {
		return nil, oerr
	}
	if err != nil {
		return nil, err
	}
	if never {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	edgeSide, phoneSide := net.Pipe()
	f.mu.Lock()
	f.phones = append(f.phones, phoneSide)
	f.mu.Unlock()
	return edgeSide, nil
}

func (f *fakeDialBacks) phone(i int) net.Conn {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.phones[i]
}

type openCall struct{ nodeID, name, connID, token string }

type fakeOpener struct {
	mu        sync.Mutex
	calls     []openCall
	errByNode map[string]error
}

func (o *fakeOpener) Open(_ context.Context, nodeID, name, connID, token string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.calls = append(o.calls, openCall{nodeID: nodeID, name: name, connID: connID, token: token})
	return o.errByNode[nodeID]
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

type fakeACMEChallenges struct {
	mu      sync.Mutex
	cert    *tls.Certificate
	err     error
	domains []string
}

func (f *fakeACMEChallenges) TLSALPNCertificate(_ context.Context, domain string) (*tls.Certificate, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.domains = append(f.domains, domain)
	if f.err != nil {
		return nil, false, f.err
	}
	return f.cert, f.cert != nil, nil
}

func (f *fakeACMEChallenges) lookups() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.domains...)
}

// testEdge builds an Edge wired to fakes + a miniredis-backed limiter.
type testEdge struct {
	e      *Edge
	rec    *recRecorder
	sink   *fakeSink
	rtr    *fakeRouter
	dial   *fakeDialBacks
	opener *fakeOpener
	chal   *fakeACMEChallenges
}

func newTestEdge(t *testing.T, cfg Config, banIP func(netip.Addr) bool, banTun func(string, string) bool) *testEdge {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { tunneltest.CloseOrLog(t, rdb) })
	lim := limit.NewLimiter(rdb, 1<<30, 1<<40, 1<<40, time.Hour) // generous caps unless a test overrides via keys

	rec := &recRecorder{}
	sink := &fakeSink{}
	rtr := &fakeRouter{}
	dial := &fakeDialBacks{}
	opener := &fakeOpener{errByNode: map[string]error{}}
	chal := &fakeACMEChallenges{}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
	e := New(cfg, banIP, banTun, rec, rtr, dial, opener, lim, sink, chal, addr)
	return &testEdge{e: e, rec: rec, sink: sink, rtr: rtr, dial: dial, opener: opener, chal: chal}
}

func containsStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
