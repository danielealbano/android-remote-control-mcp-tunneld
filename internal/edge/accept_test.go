package edge

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

func baseConfig() Config {
	return Config{
		EnrollHost: "enroll.example.test", ControlHost: "connect.example.test", TunnelDomain: "example.test",
		MaxClients: 100, ConnRate: 100, Concurrent: 8, HandshakeTimeout: time.Second,
	}
}

func TestEdge_AdmitCeiling(t *testing.T) {
	cfg := baseConfig()
	cfg.MaxClients = 2
	te := newTestEdge(t, cfg, nil)
	first, second := te.e.admit(), te.e.admit()
	if !first || !second {
		t.Fatal("first two admits must succeed")
	}
	if te.e.admit() {
		t.Fatal("third admit must be refused past --max-clients")
	}
	te.e.release()
	if !te.e.admit() {
		t.Fatal("a released slot must be re-admittable")
	}
}

func TestEdge_HandleConn_BanFirst(t *testing.T) {
	banned := netip.MustParseAddr("198.51.100.9")
	te := newTestEdge(t, baseConfig(), func(ip netip.Addr) bool { return ip == banned })
	conn := newScriptConn("198.51.100.9", nil) // no ClientHello: ban must close BEFORE any peek
	te.e.clients.Add(1)
	te.e.handleConn(context.Background(), conn)
	if !conn.isClosed() {
		t.Fatal("banned peer connection must be closed")
	}
	if !containsStr(te.rec.rejectReasons(), "ban") {
		t.Fatalf("want ban reject, got %v", te.rec.rejectReasons())
	}
}

func TestEdge_HandleConn_RateLimited(t *testing.T) {
	cfg := baseConfig()
	cfg.ConnRate = 0 // every connection over the (zero) rate
	te := newTestEdge(t, cfg, nil)
	conn := newScriptConn("198.51.100.10", nil)
	te.e.clients.Add(1)
	te.e.handleConn(context.Background(), conn)
	if !conn.isClosed() {
		t.Fatal("over-rate connection must be closed")
	}
	if !containsStr(te.rec.rejectReasons(), "conn-rate") {
		t.Fatalf("want conn-rate reject, got %v", te.rec.rejectReasons())
	}
}

func TestEdge_HandleConn_ReservedSNI_Local(t *testing.T) {
	cfg := baseConfig()
	te := newTestEdge(t, cfg, nil)
	rec := buildClientHello(cfg.ControlHost, []uint16{0x1301}, []extension{sniExt(cfg.ControlHost), alpnExt("h2"), supportedVersionsExt()})
	conn := newScriptConn("198.51.100.11", rec)
	te.e.clients.Add(1)
	go te.e.handleConn(context.Background(), conn)

	select {
	case c := <-te.e.controlLn.ch:
		// The pushed conn is a heldConn (max-clients slot holder) wrapping the metaConn carrier.
		hc, ok := c.(*heldConn)
		if !ok {
			t.Fatalf("pushed control conn must be a *heldConn holding the max-clients slot, got %T", c)
		}
		mc, ok := hc.NetConn().(*metaConn)
		if !ok {
			t.Fatalf("held conn must wrap a *metaConn carrying ConnMeta, got %T", hc.NetConn())
		}
		if mc.meta.SNI != cfg.ControlHost || mc.meta.JA4 == "" {
			t.Fatalf("pushed ConnMeta must carry SNI+JA4, got %+v", mc.meta)
		}
		before := te.e.clients.Load()
		tunneltest.CloseOrLog(t, c)
		if got := te.e.clients.Load(); got != before-1 {
			t.Fatalf("closing the pushed conn must release its max-clients slot (%d -> %d)", before, got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reserved control-host SNI must be pushed to the control listener")
	}
}

func TestEdge_HandleTunnel_UnknownRoute_Close(t *testing.T) {
	te := newTestEdge(t, baseConfig(), nil)
	te.rtr.ok = false // no route
	conn := newScriptConn("198.51.100.12", nil)
	te.e.handleTunnel(context.Background(), conn, ClientHelloInfo{SNI: "abcdef012345.example.test"})
	if !conn.isClosed() {
		t.Fatal("unknown route must close the connection")
	}
	if !containsStr(te.rec.rejectReasons(), "no-route") {
		t.Fatalf("want no-route reject, got %v", te.rec.rejectReasons())
	}
}

type unixPeerConn struct{ *scriptConn }

func (c unixPeerConn) RemoteAddr() net.Addr { return &net.UnixAddr{Name: "@peer", Net: "unix"} }

func TestEdge_UnparseablePeerRefused(t *testing.T) {
	te := newTestEdge(t, baseConfig(), func(netip.Addr) bool {
		t.Error("the ban gate must not be consulted for an unparseable peer")
		return false
	})
	sc := newScriptConn("198.51.100.30", captureClientHello(t, "enroll.example.test", "h2"))
	te.e.handleConn(context.Background(), unixPeerConn{sc})
	if !sc.isClosed() {
		t.Fatal("a connection whose peer address is not an IP must be closed")
	}
	if len(te.rec.rejects) != 0 || len(te.e.enrollLn.ch) != 0 {
		t.Fatalf("it must be refused before any gate or dispatch: rejects=%v queued=%d", te.rec.rejects, len(te.e.enrollLn.ch))
	}
}

type deadlineFailConn struct {
	net.Conn
	failClear bool
}

func (c *deadlineFailConn) SetReadDeadline(t time.Time) error {
	if t.IsZero() == c.failClear {
		return errInjectedEdge
	}
	return nil
}

var errInjectedEdge = errors.New("injected deadline failure")

func TestPeekClientHello_DeadlineErrorsReturned(t *testing.T) {
	tests := []struct {
		name      string
		failClear bool
		want      string
	}{
		{name: "set deadline fails", want: "set handshake deadline"},
		{name: "clear deadline fails", failClear: true, want: "clear handshake deadline"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a, b := net.Pipe()
			tunneltest.CloseOrLog(t, b)
			defer tunneltest.CloseOrLog(t, a)
			_, pc, err := peekClientHello(&deadlineFailConn{Conn: a, failClear: tc.failClear}, time.Second)
			if pc != nil || !errors.Is(err, errInjectedEdge) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("peekClientHello = (%v, %v), want the %q error", pc, err, tc.want)
			}
		})
	}
}

type failOnceListener struct {
	net.Listener
	calls int
}

func (l *failOnceListener) Accept() (net.Conn, error) {
	l.calls++
	if l.calls == 1 {
		return nil, errors.New("too many open files")
	}
	return nil, net.ErrClosed
}

func TestEdge_AcceptLoop_LogsAcceptFailure(t *testing.T) {
	var buf bytes.Buffer
	e := &Edge{cfg: Config{Logger: slog.New(slog.NewTextHandler(&buf, nil))}}
	e.acceptLoop(context.Background(), &failOnceListener{})
	if !strings.Contains(buf.String(), `msg="could not accept a new connection on the public port; retrying shortly" backoff=5ms err="too many open files"`) {
		t.Fatalf("an accept failure must be logged with its backoff; log = %q", buf.String())
	}
}

type readSignalConn struct {
	*scriptConn
	reading chan struct{}
	once    sync.Once
}

func (c *readSignalConn) Read(p []byte) (int, error) {
	c.once.Do(func() { close(c.reading) })
	return c.scriptConn.Read(p)
}

func runAccepted(t *testing.T, te *testEdge, conn net.Conn) {
	t.Helper()
	runAcceptedCtx(t, context.Background(), te, conn)
}

func runAcceptedCtx(t *testing.T, ctx context.Context, te *testEdge, conn net.Conn) {
	t.Helper()
	ln := &scriptedListener{steps: []func() (net.Conn, error){
		func() (net.Conn, error) { return conn, nil },
		func() (net.Conn, error) { return nil, net.ErrClosed },
	}}
	te.e.acceptLoop(ctx, ln)
}

func waitHandlers(t *testing.T, te *testEdge) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	te.e.Wait(ctx)
	if ctx.Err() != nil {
		t.Fatal("the connection handler did not return")
	}
}

func TestEdge_RoutedConns_IgnoresAConnectionStillSendingItsClientHello(t *testing.T) {
	t.Parallel()
	te := newTestEdge(t, baseConfig(), nil)
	conn := &readSignalConn{scriptConn: newScriptConn("198.51.100.20", nil), reading: make(chan struct{})}
	runAccepted(t, te, conn)
	select {
	case <-conn.reading:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler never started reading the ClientHello")
	}
	if n := te.e.RoutedConns(); n != 0 {
		t.Fatalf("a connection still sending its ClientHello must not hold the drain, RoutedConns = %d", n)
	}
	tunneltest.CloseOrLog(t, conn)
	waitHandlers(t, te)
}

func TestEdge_HandleConn_ClosesAnUnroutedConnectionWhenTheNodeStops(t *testing.T) {
	t.Parallel()
	var logs lockedBuffer
	cfg := baseConfig()
	cfg.Logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	te := newTestEdge(t, cfg, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn := &readSignalConn{scriptConn: newScriptConn("198.51.100.22", nil), reading: make(chan struct{})}
	runAcceptedCtx(t, ctx, te, conn)
	select {
	case <-conn.reading:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler never started reading the ClientHello")
	}
	cancel()
	waitHandlers(t, te)
	if !conn.isClosed() {
		t.Fatal("a connection still sending its ClientHello must be closed when the node stops")
	}
	if containsStr(te.rec.rejectReasons(), "handshake-timeout") {
		t.Fatalf("a connection closed because the node stops is not a handshake timeout, rejects=%v", te.rec.rejectReasons())
	}
	if !strings.Contains(logs.String(), "closed a public connection that had not been routed yet, because this node is stopping") {
		t.Fatalf("logs = %s", logs.String())
	}
}

func TestEdge_RoutedConns_IgnoresAConnectionWhileItsRouteIsLookedUp(t *testing.T) {
	t.Parallel()
	te := newTestEdge(t, baseConfig(), nil)
	var during atomic.Int64
	during.Store(-1)
	te.rtr.onLookup = func() { during.Store(te.e.RoutedConns()) }
	te.rtr.set("", "", false, nil)
	conn := newScriptConn("198.51.100.21", captureClientHello(t, capSNI, "h2"))
	runAccepted(t, te, conn)
	waitHandlers(t, te)
	if got := during.Load(); got != 0 {
		t.Fatalf("RoutedConns during the route lookup = %d, want 0", got)
	}
	if n := te.e.RoutedConns(); n != 0 {
		t.Fatalf("a connection without a route must not stay counted, RoutedConns = %d", n)
	}
}
