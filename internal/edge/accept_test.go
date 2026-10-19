package edge

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strings"
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
	if !strings.Contains(buf.String(), `msg="edge accept failed (backing off)" backoff=5ms err="too many open files"`) {
		t.Fatalf("an accept failure must be logged with its backoff; log = %q", buf.String())
	}
}
