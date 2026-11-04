package edge

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/report"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

type panicReadConn struct{ *scriptConn }

func (c *panicReadConn) Read([]byte) (int, error) { panic("client read boom") }

func TestAcceptLoop_PanicIsContainedToTheConnection(t *testing.T) {
	t.Parallel()
	var logs lockedBuffer
	cfg := baseConfig()
	cfg.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	te := newTestEdge(t, cfg, nil)
	te.rtr.panicLookup = true
	rep, tr := tunneltest.NewReporter(t, 0)
	conn := newScriptConn("198.51.100.9", captureClientHello(t, "abcdef012345.example.test", "h2"))
	ln := &scriptedListener{steps: []func() (net.Conn, error){
		func() (net.Conn, error) { return conn, nil },
		func() (net.Conn, error) { return nil, net.ErrClosed },
	}}

	te.e.acceptLoop(rep.Context(context.Background()), ln)
	wctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	te.e.Wait(wctx)
	if wctx.Err() != nil {
		t.Fatal("the connection handler must return after its panic")
	}
	if !conn.isClosed() {
		t.Fatal("the panicking connection must be closed")
	}
	if te.e.InFlightConns() != 0 {
		t.Fatalf("in-flight connections = %d, want 0", te.e.InFlightConns())
	}
	rep.Flush(context.Background())
	events := tr.Events("")
	if len(events) != 1 {
		t.Fatalf("want one panic event, got %d", len(events))
	}
	tags := events[0].Tags
	for k, want := range map[string]string{"where": "public connection", "tunnel": "abcdef012345", "client_ip": "198.51.100.9",
		"client_port": "51000", "sni": "abcdef012345.example.test", "alpn": "h2"} {
		if tags[k] != want {
			t.Fatalf("tag %s = %q, want %q (all tags %v)", k, tags[k], want, tags)
		}
	}
	if !strings.Contains(logs.String(), `msg="recovered from a crash; only the affected work was stopped" where="public connection"`) {
		t.Fatalf("the panic must be logged; log = %q", logs.String())
	}
}

func TestHandleTunnel_CopyPanicEndsOnlyThatSplice(t *testing.T) {
	t.Parallel()
	te := newTestEdge(t, baseConfig(), nil)
	te.rtr.set("node-b", "conn-7", true, nil)
	rep, tr := tunneltest.NewReporter(t, 1)
	client := &panicReadConn{scriptConn: newScriptConn("198.51.100.71", nil)}
	ctx := report.WithScope(rep.Context(context.Background()))
	done := make(chan struct{})
	go func() {
		defer close(done)
		te.e.handleTunnel(ctx, client, ClientHelloInfo{SNI: "abcdef012345.example.test", ALPN: "h2", TLSVersion: "1.3", JA4: "t13d"})
	}()
	phone := waitPhone(t, te, 0)
	defer tunneltest.CloseOrLog(t, phone)
	waitDone(t, done, 5*time.Second)

	te.sink.mu.Lock()
	var end PublicEvent
	for _, ev := range te.sink.events {
		if ev.Event == "end" {
			end = ev
		}
	}
	te.sink.mu.Unlock()
	if end.CloseReason != store.CloseError {
		t.Fatalf("close reason = %q, want %q", end.CloseReason, store.CloseError)
	}
	rep.Flush(context.Background())
	issues := tr.Events("")
	if len(issues) != 1 || issues[0].Tags["where"] != "public connection upload" || issues[0].Tags["tunnel"] != "abcdef012345" {
		t.Fatalf("want one panic event from the upload copy, got %d", len(issues))
	}
	txs := tr.Events("transaction")
	if len(txs) != 1 {
		t.Fatalf("want one connection transaction, got %d", len(txs))
	}
	tags := txs[0].Tags
	for k, want := range map[string]string{"tunnel": "abcdef012345", "client_ip": "198.51.100.71", "client_port": "51000",
		"sni": "abcdef012345.example.test", "alpn": "h2", "tls_version": "1.3", "ja4": "t13d", "close_reason": store.CloseError,
		"conn_id": end.Conn, "bytes_in": "0", "bytes_out": "0"} {
		if tags[k] != want {
			t.Fatalf("transaction tag %s = %q, want %q (all tags %v)", k, tags[k], want, tags)
		}
	}
	if txs[0].Transaction != "public connection" {
		t.Fatalf("transaction name = %q", txs[0].Transaction)
	}
}

func TestHandleTunnel_NoTraceWithoutAPhone(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		sni        string
		setup      func(*testing.T, *testEdge)
		wantReject string
		wantOpen   bool
	}{
		{name: "unknown host", sni: "unknown.example.test", wantReject: "no-route"},
		{name: "no route", sni: "abcdef012345.example.test", wantReject: "no-route"},
		{name: "stream cap", sni: capSNI, wantReject: "stream-cap", setup: func(t *testing.T, te *testEdge) {
			te.rtr.set("node-a", "conn-1", true, nil)
			fillSlots(t, te, baseConfig().Concurrent)
		}},
		{name: "OPEN fails", sni: "abcdef012345.example.test", wantReject: "no-route", wantOpen: true, setup: func(_ *testing.T, te *testEdge) {
			te.rtr.set("node-a", "conn-1", true, nil)
			te.opener.errByNode["node-a"] = errors.New("owner unreachable")
		}},
		{name: "dial-back fails", sni: "abcdef012345.example.test", wantReject: "no-route", wantOpen: true, setup: func(_ *testing.T, te *testEdge) {
			te.rtr.set("node-a", "conn-1", true, nil)
			te.dial.err = errors.New("the phone never dialed back")
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			te := newTestEdge(t, baseConfig(), nil)
			if tc.setup != nil {
				tc.setup(t, te)
			}
			rep, tr := tunneltest.NewReporter(t, 1)
			client := newScriptConn("198.51.100.72", nil)
			te.e.handleTunnel(report.WithScope(rep.Context(context.Background())), client, ClientHelloInfo{SNI: tc.sni})
			if !client.isClosed() || !containsStr(te.rec.rejectReasons(), tc.wantReject) || (openCalls(te) > 0) != tc.wantOpen {
				t.Fatalf("closed = %v, rejections = %v, OPEN calls = %d: want the client closed as %q, OPEN sent = %v",
					client.isClosed(), te.rec.rejectReasons(), openCalls(te), tc.wantReject, tc.wantOpen)
			}
			rep.Flush(context.Background())
			if n := len(tr.Events("transaction")); n != 0 {
				t.Fatalf("a connection that never reached a phone must not be traced, got %d transactions", n)
			}
		})
	}
}

type panicReadNetConn struct{ net.Conn }

func (c *panicReadNetConn) Read([]byte) (int, error) { panic("phone read boom") }

func TestHandleTunnel_DownloadPanicEndsOnlyThatSplice(t *testing.T) {
	t.Parallel()
	te := newTestEdge(t, baseConfig(), nil)
	te.rtr.set("node-b", "conn-7", true, nil)
	te.dial.wrapEdge = func(c net.Conn) net.Conn { return &panicReadNetConn{Conn: c} }
	rep, tr := tunneltest.NewReporter(t, 0)
	client := newScriptConn("198.51.100.73", nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		te.e.handleTunnel(report.WithScope(rep.Context(context.Background())), client, ClientHelloInfo{SNI: "abcdef012345.example.test"})
	}()
	phone := waitPhone(t, te, 0)
	defer tunneltest.CloseOrLog(t, phone)
	waitDone(t, done, 5*time.Second)
	if !client.isClosed() {
		t.Fatal("the public client must be closed")
	}
	rep.Flush(context.Background())
	issues := tr.Events("")
	if len(issues) != 1 || issues[0].Tags["where"] != "public connection download" {
		t.Fatalf("want one panic event from the download copy, got %d", len(issues))
	}
}

func TestHandleTunnel_PanicStillClosesTheAccounting(t *testing.T) {
	t.Parallel()
	te := newTestEdge(t, baseConfig(), nil)
	te.rtr.set("node-b", "conn-7", true, nil)
	te.sink.panicOnStart = true
	client := newScriptConn("198.51.100.74", nil)
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		te.e.handleTunnel(context.Background(), client, ClientHelloInfo{SNI: "abcdef012345.example.test"})
	}()
	if recovered != "conn log boom" {
		t.Fatalf("the panic must continue to the connection guard, recovered %v", recovered)
	}
	te.rec.mu.Lock()
	opens, closes, sOpen, sClose := te.rec.opens, te.rec.closes, te.rec.sOpen, te.rec.sClose
	te.rec.mu.Unlock()
	if opens != 1 || closes != 1 || sOpen != 1 || sClose != 1 {
		t.Fatalf("connection gauges opened %d/%d and closed %d/%d, want each closed once", opens, sOpen, closes, sClose)
	}
	te.sink.mu.Lock()
	events := append([]PublicEvent(nil), te.sink.events...)
	te.sink.mu.Unlock()
	if len(events) != 1 || events[0].Event != "end" || events[0].CloseReason != store.CloseError {
		t.Fatalf("conn-log events = %+v, want one end event with reason %q", events, store.CloseError)
	}
	if !client.isClosed() {
		t.Fatal("the public client must be closed")
	}
}

func TestAcceptLoop_ACMEChallengePanicCarriesTheClientHello(t *testing.T) {
	t.Parallel()
	te := newTestEdge(t, baseConfig(), nil)
	te.chal.panics = true
	rep, tr := tunneltest.NewReporter(t, 0)
	conn := newScriptConn("198.51.100.10", captureClientHello(t, "abcdef012345.example.test", acmeTLS1Protocol))
	ln := &scriptedListener{steps: []func() (net.Conn, error){
		func() (net.Conn, error) { return conn, nil },
		func() (net.Conn, error) { return nil, net.ErrClosed },
	}}
	te.e.acceptLoop(rep.Context(context.Background()), ln)
	wctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	te.e.Wait(wctx)
	if wctx.Err() != nil || !conn.isClosed() {
		t.Fatal("the panicking challenge connection must be closed and its handler must return")
	}
	rep.Flush(context.Background())
	events := tr.Events("")
	if len(events) != 1 {
		t.Fatalf("want one panic event, got %d", len(events))
	}
	for _, k := range []string{"sni", "alpn", "tls_version", "ja4", "client_ip"} {
		if events[0].Tags[k] == "" {
			t.Errorf("the panic event must carry %s, tags %v", k, events[0].Tags)
		}
	}
	if events[0].Tags["alpn"] != acmeTLS1Protocol {
		t.Errorf("alpn tag = %q, want %q", events[0].Tags["alpn"], acmeTLS1Protocol)
	}
}
