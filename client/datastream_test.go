package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/wire"
)

var errInjected = errors.New("injected failure")

type failingBody struct{ io.Reader }

func (failingBody) Close() error { return errInjected }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func newLoggedClient() (*Client, *bytes.Buffer) {
	var buf bytes.Buffer
	return &Client{logger: slog.New(slog.NewTextHandler(&buf, nil))}, &buf
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func newRawListener(t *testing.T, serve func(net.Conn)) (string, *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tunneltest.CloseOrLog(t, ln) })
	var accepts atomic.Int64
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				if !errors.Is(aerr, net.ErrClosed) {
					tunneltest.Logger().Warn("test listener accept failed", "err", aerr)
				}
				return
			}
			accepts.Add(1)
			go serve(c)
		}
	}()
	return ln.Addr().String(), &accepts
}

func TestClient_HandleOpen_InvalidOpenIgnored(t *testing.T) {
	addr, accepts := newRawListener(t, func(c net.Conn) { tunneltest.CloseLogged(c) })
	tests := []struct {
		name    string
		payload string
		want    string
	}{
		{name: "undecodable payload", payload: "{", want: `msg="malformed OPEN payload from the server (ignored)"`},
		{name: "empty token", payload: `{"addr":"` + addr + `","use_https":false}`, want: `msg="invalid OPEN from the server (ignored)"`},
		{name: "empty addr", payload: `{"token":"TOKEN","use_https":false}`, want: `msg="invalid OPEN from the server (ignored)"`},
		{name: "mtls without https", payload: `{"token":"TOKEN","addr":"` + addr + `","use_https":false,"use_mtls":true}`, want: `msg="invalid OPEN from the server (ignored)"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, buf := newLoggedClient()
			c.handleOpen(context.Background(), []byte(tc.payload))
			if !strings.Contains(buf.String(), tc.want) || !strings.Contains(buf.String(), "level=WARN") {
				t.Fatalf("the ignored OPEN must be logged at Warn; log = %q", buf.String())
			}
		})
	}
	if n := accepts.Load(); n != 0 {
		t.Fatalf("an invalid OPEN must dial nothing, got %d connections", n)
	}
}

func echoBackend(s io.ReadWriteCloser) {
	if _, err := io.Copy(s, s); err != nil {
		tunneltest.Logger().Debug("echo backend ended", "err", err)
	}
}

func runClient(t *testing.T, c *Client) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		if err := c.Run(ctx); err != nil && ctx.Err() == nil {
			tunneltest.Logger().Warn("client run failed", "err", err)
		}
	}()
	return cancel
}

func echoThrough(t *testing.T, conn net.Conn, msg string) {
	t.Helper()
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != msg {
		t.Fatalf("echo = %q, want %q", buf, msg)
	}
}

func dialBackHandshake(t *testing.T, ts *testServer) tls.ConnectionState {
	t.Helper()
	for {
		select {
		case cs := <-ts.handshakes:
			if cs.NegotiatedProtocol == "http/1.1" {
				return cs
			}
		case <-time.After(3 * time.Second):
			t.Fatal("no http/1.1 dial-back handshake was seen")
		}
	}
}

func TestClient_HandleOpen_DialsBackAndSplices(t *testing.T) {
	ts := startTestServer(t)
	runClient(t, ts.newClient(t, echoBackend))
	if !waitFor(t, 3*time.Second, func() bool { return ts.mgr.HasConn(testName) }) {
		t.Fatal("control connect must bind the route")
	}
	conn, err := ts.dialBack(t, "TOKEN-MTLS", true, true)
	if err != nil {
		t.Fatal(err)
	}
	defer tunneltest.CloseOrLog(t, conn)
	echoThrough(t, conn, "mtls-dial-back")
	cs := dialBackHandshake(t, ts)
	if len(cs.PeerCertificates) == 0 || cs.PeerCertificates[0].Subject.CommonName != testName {
		t.Fatalf("the mTLS dial-back must present the identity cert, got %d certs", len(cs.PeerCertificates))
	}
}

func TestClient_HandleOpen_TLSWithoutClientCert(t *testing.T) {
	ts := startTestServerMode(t, false)
	runClient(t, ts.newClient(t, echoBackend))
	if !waitFor(t, 3*time.Second, func() bool { return ts.mgr.HasConn(testName) }) {
		t.Fatal("control connect must bind the route")
	}
	conn, err := ts.dialBack(t, "TOKEN-TLS", true, false)
	if err != nil {
		t.Fatal(err)
	}
	defer tunneltest.CloseOrLog(t, conn)
	echoThrough(t, conn, "tls-dial-back")
	if cs := dialBackHandshake(t, ts); len(cs.PeerCertificates) != 0 {
		t.Fatalf("a dial-back without use_mtls must present no client cert, got %d", len(cs.PeerCertificates))
	}
}

func TestClient_HandleOpen_Plain(t *testing.T) {
	ts := startTestServerMode(t, false)
	runClient(t, ts.newClient(t, echoBackend))
	if !waitFor(t, 3*time.Second, func() bool { return ts.mgr.HasConn(testName) }) {
		t.Fatal("control connect must bind the route")
	}
	conn, err := ts.dialBack(t, "TOKEN-PLAIN", false, false)
	if err != nil {
		t.Fatal(err)
	}
	defer tunneltest.CloseOrLog(t, conn)
	echoThrough(t, conn, "plain-dial-back")
}

func TestClient_HandleOpen_RefusedClosesWithoutBackend(t *testing.T) {
	ts := startTestServer(t)
	buf := &syncBuf{}
	var invoked atomic.Bool
	c := ts.newClient(t, func(io.ReadWriteCloser) { invoked.Store(true) },
		WithLogger(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))))
	runClient(t, c)
	if !waitFor(t, 3*time.Second, func() bool { return ts.mgr.HasConn(testName) }) {
		t.Fatal("control connect must bind the route")
	}
	_, _, connID, _, err := ts.reg.LookupRoute(context.Background(), testName)
	if err != nil {
		t.Fatal(err)
	}
	if err := ts.mgr.SendOpen(context.Background(), testName, connID, wire.OpenPayload{Token: "UNKNOWN", Addr: ts.dialAdr, UseHTTPS: true, UseMTLS: true}); err != nil {
		t.Fatal(err)
	}
	if !waitFor(t, 3*time.Second, func() bool { return strings.Contains(buf.String(), "dial-back failed") }) {
		t.Fatalf("a refused dial-back must be logged; log = %q", buf.String())
	}
	if !strings.Contains(buf.String(), "404") || !strings.Contains(buf.String(), "level=DEBUG") {
		t.Fatalf("the refusal must be a Debug line carrying the 404; log = %q", buf.String())
	}
	if invoked.Load() {
		t.Fatal("the backend must not be invoked for a refused dial-back")
	}
}

func TestClient_DialBack_KeepsBytesSentWithThe101(t *testing.T) {
	addr, _ := newRawListener(t, func(c net.Conn) {
		defer tunneltest.CloseLogged(c)
		if _, err := http.ReadRequest(bufio.NewReader(c)); err != nil {
			tunneltest.Logger().Warn("test server read failed", "err", err)
			return
		}
		if _, err := c.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: tunneld-dial\r\n\r\nhello")); err != nil {
			tunneltest.Logger().Warn("test server write failed", "err", err)
		}
		if _, err := io.Copy(io.Discard, c); err != nil {
			tunneltest.Logger().Debug("test server drain ended", "err", err)
		}
	})
	got := make(chan string, 1)
	c, _ := newLoggedClient()
	c.controlHost = testControlHost
	c.dialBackTimeout = time.Second
	c.backend = func(s io.ReadWriteCloser) {
		buf := make([]byte, 5)
		if _, err := io.ReadFull(s, buf); err != nil {
			got <- "read error: " + err.Error()
			return
		}
		got <- string(buf)
	}
	c.handleOpen(context.Background(), []byte(`{"token":"TOKEN","addr":"`+addr+`","use_https":false}`))
	select {
	case first := <-got:
		if first != "hello" {
			t.Fatalf("the backend read %q first, want the bytes sent with the 101", first)
		}
	default:
		t.Fatal("the backend was not invoked")
	}
}

func TestClient_DialBack_HonoursTimeout(t *testing.T) {
	addr, _ := newRawListener(t, func(c net.Conn) {
		defer tunneltest.CloseLogged(c)
		if _, err := io.Copy(io.Discard, c); err != nil {
			tunneltest.Logger().Debug("test server drain ended", "err", err)
		}
	})
	c, _ := newLoggedClient()
	c.controlHost = testControlHost
	if err := WithDialBackTimeout(200 * time.Millisecond)(c); err != nil {
		t.Fatal(err)
	}
	var invoked atomic.Bool
	c.backend = func(io.ReadWriteCloser) { invoked.Store(true) }
	start := time.Now()
	c.handleOpen(context.Background(), []byte(`{"token":"TOKEN","addr":"`+addr+`","use_https":false}`))
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("the dial-back was not bounded by its timeout (took %s)", elapsed)
	}
	if invoked.Load() {
		t.Fatal("the backend must not be invoked when the upgrade times out")
	}
}

func TestClient_DialBack_UpgradeAbortedWhenRunStops(t *testing.T) {
	accepted := make(chan net.Conn, 1)
	addr, _ := newRawListener(t, func(c net.Conn) { accepted <- c })
	c, _ := newLoggedClient()
	c.controlHost = testControlHost
	c.dialBackTimeout = time.Minute
	var invoked atomic.Bool
	c.backend = func(io.ReadWriteCloser) { invoked.Store(true) }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	returned := make(chan struct{})
	go func() {
		c.handleOpen(ctx, []byte(`{"token":"TOKEN","addr":"`+addr+`","use_https":false}`))
		close(returned)
	}()
	var srv net.Conn
	select {
	case srv = <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("the dial-back never connected")
	}
	defer tunneltest.CloseOrLog(t, srv)
	cancel()
	select {
	case <-returned:
	case <-time.After(3 * time.Second):
		t.Fatal("the dial-back upgrade outlived Run's context")
	}
	if invoked.Load() {
		t.Fatal("the backend must not be invoked for an aborted upgrade")
	}
	if err := srv.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, srv); err != nil {
		t.Fatalf("the aborted dial-back socket must be closed, read = %v", err)
	}
}

func TestNew_RejectsNonPositiveDialBackTimeout(t *testing.T) {
	if _, err := New("127.0.0.1:1", testControlHost, testTunnelDomain, nil, nil, nil, WithDialBackTimeout(0)); err == nil {
		t.Fatal("a zero dial-back timeout must be rejected")
	}
}

func TestClient_DialBack_ClosedWhenRunStops(t *testing.T) {
	ts := startTestServer(t)
	entered := make(chan struct{})
	readDone := make(chan error, 1)
	cancel := runClient(t, ts.newClient(t, func(s io.ReadWriteCloser) {
		close(entered)
		_, err := s.Read(make([]byte, 1))
		readDone <- err
	}))
	if !waitFor(t, 3*time.Second, func() bool { return ts.mgr.HasConn(testName) }) {
		t.Fatal("control connect must bind the route")
	}
	conn, err := ts.dialBack(t, "TOKEN-STOP", true, true)
	if err != nil {
		t.Fatal(err)
	}
	defer tunneltest.CloseOrLog(t, conn)
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("the backend was not invoked")
	}
	cancel()
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("the backend's Read must fail once the connection is closed")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the dial-back connection outlived Run")
	}
}

func TestClient_Renew_LogsFailures(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		want    string
	}{
		{name: "undecodable payload", payload: "{", want: `msg="malformed RENEW_NUDGE payload from the server (ignored)"`},
		{name: "missing nonce", payload: "{}", want: `msg="RENEW_NUDGE without a nonce from the server (ignored)"`},
		{name: "issuance fails", payload: `{"nonce":"00"}`, want: `msg="renew after a RENEW_NUDGE failed (keeping the current certs)"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, buf := newLoggedClient()
			original := &Identity{Name: testName, CA: "test"}
			c.ident = original
			c.controlHost = testControlHost
			c.tunnelDomain = testTunnelDomain
			c.hc = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return nil, errInjected
			})}
			c.renew(context.Background(), []byte(tc.payload))
			if !strings.Contains(buf.String(), tc.want) {
				t.Fatalf("the failed renewal must be logged; log = %q", buf.String())
			}
			if c.Identity() != original {
				t.Fatal("a failed renewal must keep the current identity")
			}
		})
	}
}
