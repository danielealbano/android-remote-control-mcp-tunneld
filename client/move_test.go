package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/wire"
)

type moveServer struct {
	addr    string
	accepts atomic.Int64
	streams atomic.Int64
	pongs   atomic.Int64
	bound   chan struct{}
	ended   chan struct{}
	release chan struct{}
	ping    chan struct{}
	pingF   []byte
}

type moveListener struct {
	net.Listener
	s *moveServer
}

func (l *moveListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.s.accepts.Add(1)
	}
	return c, err
}

func startMoveServer(t *testing.T, ca *testCA, handler func(s *moveServer, w http.ResponseWriter, r *http.Request)) *moveServer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(ca.signLeaf(t, testControlHost, &key.PublicKey, true, []string{testControlHost}), keyPEM(t, key))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &moveServer{addr: ln.Addr().String(), bound: make(chan struct{}, 8), ended: make(chan struct{}, 8),
		release: make(chan struct{}), ping: make(chan struct{}, 8), pingF: frame(t, wire.CtrlPing, nil)}
	tlsConf := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2"}}
	srv := &http.Server{ReadHeaderTimeout: 5 * time.Second, TLSConfig: tlsConf,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.streams.Add(1)
			defer func() { s.ended <- struct{}{} }()
			handler(s, w, r)
		})}
	tunneltest.ServeHTTP(t, srv, tls.NewListener(&moveListener{Listener: ln, s: s}, tlsConf))
	return s
}

func frame(t *testing.T, ct wire.ControlType, payload any) []byte {
	t.Helper()
	f, err := wire.EncodeControl(ct, payload)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func countPongs(s *moveServer, r *http.Request) {
	for {
		ct, _, err := readControlFrame(r.Body)
		if err != nil {
			return
		}
		if ct == wire.CtrlPong {
			s.pongs.Add(1)
		}
	}
}

func bindAndHold(s *moveServer, w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.(http.Flusher).Flush()
	go countPongs(s, r)
	s.bound <- struct{}{}
	for {
		select {
		case <-r.Context().Done():
			return
		case <-s.release:
			return
		case <-s.ping:
			if _, err := w.Write(s.pingF); err != nil {
				return
			}
			w.(http.Flusher).Flush()
		}
	}
}

func moveThenHold(t *testing.T, addrs []string) func(s *moveServer, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	mv := frame(t, wire.CtrlMove, wire.MovePayload{Addrs: addrs})
	first := atomic.Bool{}
	return func(s *moveServer, w http.ResponseWriter, r *http.Request) {
		if !first.CompareAndSwap(false, true) {
			bindAndHold(s, w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		go countPongs(s, r)
		s.bound <- struct{}{}
		if _, err := w.Write(mv); err != nil {
			return
		}
		w.(http.Flusher).Flush()
		for {
			select {
			case <-r.Context().Done():
				return
			case <-s.release:
				return
			case <-s.ping:
				if _, err := w.Write(s.pingF); err != nil {
					return
				}
				w.(http.Flusher).Flush()
			}
		}
	}
}

func newMoveClient(t *testing.T, dialAddr string, ca *testCA, logger *slog.Logger, opts ...Option) *Client {
	t.Helper()
	c, err := New(dialAddr, testEnrollHost, testControlHost, testTunnelDomain, ca.pool, newCAIdentity(t, ca),
		func(io.ReadWriteCloser) {}, append([]Option{WithLogger(logger)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func waitSignal(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not happen within 5s", what)
	}
}

func TestRun_MoveOpensANewConnectionAndKeepsTheOldOne(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	b := startMoveServer(t, ca, func(s *moveServer, w http.ResponseWriter, r *http.Request) { bindAndHold(s, w, r) })
	a := startMoveServer(t, ca, moveThenHold(t, []string{b.addr}))
	c := newMoveClient(t, a.addr, ca, tunneltest.Logger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runResult(ctx, c)
	waitSignal(t, a.bound, "the bind on the first node")
	waitSignal(t, b.bound, "the bind on the MOVE target")
	select {
	case <-a.ended:
		t.Fatal("the phone must keep the connection that carried the MOVE open")
	case <-time.After(300 * time.Millisecond):
	}
	a.ping <- struct{}{}
	deadline := time.Now().Add(5 * time.Second)
	for a.pongs.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the moved-away connection must still answer PING")
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(a.release)
	waitSignal(t, a.ended, "the end of the old connection")
	select {
	case err := <-done:
		t.Fatalf("Run returned %v when the old connection ended; it must keep serving the new one", err)
	case <-time.After(300 * time.Millisecond):
	}
	b.ping <- struct{}{}
	deadline = time.Now().Add(5 * time.Second)
	for b.pongs.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the new connection must answer PING")
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(b.release)
	if err := waitRun(t, done, 5*time.Second); err == nil {
		t.Fatal("Run must return the error that ended the current connection")
	}
	c.Close()
}

func TestRun_MoveFallsBackToTheDialAddressOnANewConnection(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	unreachable := tunneltest.FreeAddr(t)
	a := startMoveServer(t, ca, moveThenHold(t, []string{unreachable}))
	c := newMoveClient(t, a.addr, ca, tunneltest.Logger())
	ctx, cancel := context.WithCancel(context.Background())
	done := runResult(ctx, c)
	t.Cleanup(func() {
		cancel()
		if err := waitRun(t, done, 5*time.Second); err != nil {
			t.Logf("Run after cancel: %v", err)
		}
		c.Close()
	})
	waitSignal(t, a.bound, "the first bind")
	waitSignal(t, a.bound, "the bind after the fallback")
	if n := a.accepts.Load(); n != 2 {
		t.Fatalf("the fallback must open a new connection, accepted %d", n)
	}
	if n := a.streams.Load(); n != 2 {
		t.Fatalf("control streams = %d, want 2 (the moved one stays open)", n)
	}
}

func TestRun_MoveSkipsInvalidAddresses(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	b := startMoveServer(t, ca, func(s *moveServer, w http.ResponseWriter, r *http.Request) { bindAndHold(s, w, r) })
	a := startMoveServer(t, ca, moveThenHold(t, []string{"not-an-address", ":443", b.addr}))
	logs := &syncBuf{}
	c := newMoveClient(t, a.addr, ca, slog.New(slog.NewTextHandler(logs, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	done := runResult(ctx, c)
	t.Cleanup(func() {
		cancel()
		if err := waitRun(t, done, 5*time.Second); err != nil {
			t.Logf("Run after cancel: %v", err)
		}
		c.Close()
	})
	waitSignal(t, a.bound, "the first bind")
	waitSignal(t, b.bound, "the bind on the valid target")
	if n := strings.Count(logs.String(), "invalid MOVE address"); n != 2 {
		t.Fatalf("invalid MOVE addresses logged %d times, want 2: %s", n, logs.String())
	}
}

func TestRun_MoveAnsweredWithoutABindIsFollowed(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	b := startMoveServer(t, ca, func(s *moveServer, w http.ResponseWriter, r *http.Request) { bindAndHold(s, w, r) })
	mv := frame(t, wire.CtrlMove, wire.MovePayload{Addrs: []string{b.addr}})
	a := startMoveServer(t, ca, func(_ *moveServer, w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(mv); err != nil {
			return
		}
		w.(http.Flusher).Flush()
	})
	c := newMoveClient(t, a.addr, ca, tunneltest.Logger())
	ctx, cancel := context.WithCancel(context.Background())
	done := runResult(ctx, c)
	t.Cleanup(func() {
		cancel()
		if err := waitRun(t, done, 5*time.Second); err != nil {
			t.Logf("Run after cancel: %v", err)
		}
		c.Close()
	})
	waitSignal(t, b.bound, "the bind on the MOVE target")
}

func TestRun_MalformedMoveIsIgnored(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	bad := []byte{byte(wire.CtrlMove), 0, 0, 0, 1, '{'}
	a := startMoveServer(t, ca, func(s *moveServer, w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		if _, err := w.Write(bad); err != nil {
			return
		}
		w.(http.Flusher).Flush()
		s.bound <- struct{}{}
		<-r.Context().Done()
	})
	c := newMoveClient(t, a.addr, ca, tunneltest.Logger())
	ctx, cancel := context.WithCancel(context.Background())
	done := runResult(ctx, c)
	waitSignal(t, a.bound, "the bind")
	select {
	case err := <-done:
		t.Fatalf("Run returned %v after a malformed MOVE", err)
	case <-time.After(300 * time.Millisecond):
	}
	if n := a.accepts.Load(); n != 1 {
		t.Fatalf("a malformed MOVE must not open a connection, accepted %d", n)
	}
	cancel()
	if err := waitRun(t, done, 5*time.Second); err != nil {
		t.Fatalf("Run after cancel = %v, want nil", err)
	}
	c.Close()
}

func TestRun_MoveOnTheNewConnectionIsFollowed(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	c3 := startMoveServer(t, ca, func(s *moveServer, w http.ResponseWriter, r *http.Request) { bindAndHold(s, w, r) })
	b := startMoveServer(t, ca, moveThenHold(t, []string{c3.addr}))
	a := startMoveServer(t, ca, moveThenHold(t, []string{b.addr}))
	c := newMoveClient(t, a.addr, ca, tunneltest.Logger())
	ctx, cancel := context.WithCancel(context.Background())
	done := runResult(ctx, c)
	waitSignal(t, a.bound, "the bind on the first node")
	waitSignal(t, b.bound, "the bind on the first MOVE target")
	waitSignal(t, c3.bound, "the bind on the second MOVE target")
	select {
	case <-a.ended:
		t.Fatal("the first moved-away connection must stay open")
	case <-b.ended:
		t.Fatal("the second moved-away connection must stay open")
	case <-time.After(300 * time.Millisecond):
	}
	cancel()
	if err := waitRun(t, done, 5*time.Second); err != nil {
		t.Logf("Run after cancel: %v", err)
	}
	c.Close()
}

func TestRun_SecondMoveOnAMovedConnectionIsIgnored(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	b := startMoveServer(t, ca, func(s *moveServer, w http.ResponseWriter, r *http.Request) { bindAndHold(s, w, r) })
	other := startMoveServer(t, ca, func(s *moveServer, w http.ResponseWriter, r *http.Request) { bindAndHold(s, w, r) })
	first := frame(t, wire.CtrlMove, wire.MovePayload{Addrs: []string{b.addr}})
	second := frame(t, wire.CtrlMove, wire.MovePayload{Addrs: []string{other.addr}})
	secondSent := make(chan struct{})
	a := startMoveServer(t, ca, func(s *moveServer, w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		s.bound <- struct{}{}
		if _, err := w.Write(first); err != nil {
			return
		}
		w.(http.Flusher).Flush()
		<-b.bound
		if _, err := w.Write(second); err != nil {
			return
		}
		w.(http.Flusher).Flush()
		close(secondSent)
		<-r.Context().Done()
	})
	c := newMoveClient(t, a.addr, ca, tunneltest.Logger())
	ctx, cancel := context.WithCancel(context.Background())
	done := runResult(ctx, c)
	waitSignal(t, a.bound, "the bind on the first node")
	waitSignal(t, secondSent, "the second MOVE")
	time.Sleep(300 * time.Millisecond)
	if n := other.accepts.Load(); n != 0 {
		t.Fatalf("a second MOVE on a moved connection must be ignored, the other node accepted %d connections", n)
	}
	cancel()
	if err := waitRun(t, done, 5*time.Second); err != nil {
		t.Logf("Run after cancel: %v", err)
	}
	c.Close()
}

func TestRun_MovedConnectionOutlivesTheNewOne(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	b := startMoveServer(t, ca, func(s *moveServer, w http.ResponseWriter, r *http.Request) { bindAndHold(s, w, r) })
	a := startMoveServer(t, ca, moveThenHold(t, []string{b.addr}))
	c := newMoveClient(t, a.addr, ca, tunneltest.Logger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runResult(ctx, c)
	waitSignal(t, a.bound, "the bind on the first node")
	waitSignal(t, b.bound, "the bind on the MOVE target")
	close(b.release)
	if err := waitRun(t, done, 5*time.Second); err == nil {
		t.Fatal("Run must return the error that ended the current connection")
	}
	select {
	case <-a.ended:
		t.Fatal("the phone must not close the moved-away connection when the new one ends")
	case <-time.After(500 * time.Millisecond):
	}
	a.ping <- struct{}{}
	deadline := time.Now().Add(5 * time.Second)
	for a.pongs.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the moved-away connection must keep answering PING after Run returned")
		}
		time.Sleep(10 * time.Millisecond)
	}
	c.Close()
	waitSignal(t, a.ended, "the moved-away connection ending on Close")
}

func TestRun_MoveSkipsATargetThatNeverCompletesTLS(t *testing.T) {
	t.Parallel()
	hole, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	held := make(chan net.Conn, 4)
	go func() {
		for {
			conn, err := hole.Accept()
			if err != nil {
				return
			}
			held <- conn
		}
	}()
	t.Cleanup(func() {
		tunneltest.CloseOrLog(t, hole)
		for {
			select {
			case conn := <-held:
				tunneltest.CloseOrLog(t, conn)
			default:
				return
			}
		}
	})
	ca := newTestCA(t)
	b := startMoveServer(t, ca, func(s *moveServer, w http.ResponseWriter, r *http.Request) { bindAndHold(s, w, r) })
	a := startMoveServer(t, ca, moveThenHold(t, []string{hole.Addr().String(), b.addr}))
	c := newMoveClient(t, a.addr, ca, tunneltest.Logger(), WithControlDialTimeout(300*time.Millisecond))
	ctx, cancel := context.WithCancel(context.Background())
	done := runResult(ctx, c)
	waitSignal(t, a.bound, "the bind on the first node")
	waitSignal(t, b.bound, "the bind on the target after the one that never completes TLS")
	cancel()
	if err := waitRun(t, done, 5*time.Second); err != nil {
		t.Logf("Run after cancel: %v", err)
	}
	c.Close()
}

func TestRun_MoveFromTheFallbackWaitsBeforeItIsFollowed(t *testing.T) {
	t.Parallel()
	const wait = 400 * time.Millisecond
	ca := newTestCA(t)
	unreachable := tunneltest.FreeAddr(t)
	var times []time.Time
	var mu sync.Mutex
	mv := frame(t, wire.CtrlMove, wire.MovePayload{Addrs: []string{unreachable}})
	a := startMoveServer(t, ca, func(s *moveServer, w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		times = append(times, time.Now())
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(mv); err != nil {
			return
		}
		w.(http.Flusher).Flush()
		s.bound <- struct{}{}
		<-r.Context().Done()
	})
	c := newMoveClient(t, a.addr, ca, tunneltest.Logger(), WithMoveFallbackWait(wait))
	ctx, cancel := context.WithCancel(context.Background())
	done := runResult(ctx, c)
	for i := range 3 {
		waitSignal(t, a.bound, "control stream "+strconv.Itoa(i+1))
	}
	cancel()
	if err := waitRun(t, done, 5*time.Second); err != nil {
		t.Logf("Run after cancel: %v", err)
	}
	c.Close()
	mu.Lock()
	defer mu.Unlock()
	if gap := times[2].Sub(times[1]); gap < wait {
		t.Fatalf("a MOVE answered by the fallback connection was followed after %s, want the %s wait", gap, wait)
	}
}

func TestRun_MoveWithoutAddressesIsIgnored(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	for _, payload := range []string{`{}`, `{"addrs":null}`, `{"addrs":[]}`} {
		t.Run(payload, func(t *testing.T) {
			bad := append([]byte{byte(wire.CtrlMove), 0, 0, 0, byte(len(payload))}, payload...)
			a := startMoveServer(t, ca, func(s *moveServer, w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				if _, err := w.Write(bad); err != nil {
					return
				}
				w.(http.Flusher).Flush()
				s.bound <- struct{}{}
				<-r.Context().Done()
			})
			c := newMoveClient(t, a.addr, ca, tunneltest.Logger())
			ctx, cancel := context.WithCancel(context.Background())
			done := runResult(ctx, c)
			waitSignal(t, a.bound, "the bind")
			select {
			case err := <-done:
				t.Fatalf("Run returned %v after a MOVE without addresses", err)
			case <-time.After(300 * time.Millisecond):
			}
			if n := a.accepts.Load(); n != 1 {
				t.Fatalf("a MOVE without addresses must not open a connection, accepted %d", n)
			}
			cancel()
			if err := waitRun(t, done, 5*time.Second); err != nil {
				t.Fatalf("Run after cancel = %v, want nil", err)
			}
			c.Close()
		})
	}
}

func TestRun_MovedAwayConnectionErrorIsLogged(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	b := startMoveServer(t, ca, func(s *moveServer, w http.ResponseWriter, r *http.Request) { bindAndHold(s, w, r) })
	mv := frame(t, wire.CtrlMove, wire.MovePayload{Addrs: []string{b.addr}})
	oversized := []byte{byte(wire.CtrlPing), 0x7f, 0xff, 0xff, 0xff}
	a := startMoveServer(t, ca, func(s *moveServer, w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(mv); err != nil {
			return
		}
		w.(http.Flusher).Flush()
		s.bound <- struct{}{}
		<-b.bound
		if _, err := w.Write(oversized); err != nil {
			return
		}
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	logs := &syncBuf{}
	c := newMoveClient(t, a.addr, ca, slog.New(slog.NewTextHandler(logs, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	done := runResult(ctx, c)
	waitSignal(t, a.bound, "the bind on the first node")
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(logs.String(), `level=WARN msg="moved-away control connection ended"`) {
		if time.Now().After(deadline) {
			t.Fatalf("the moved-away connection's error must be logged at Warn, got %q", logs.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := waitRun(t, done, 5*time.Second); err != nil {
		t.Logf("Run after cancel: %v", err)
	}
	c.Close()
}

func refuse(_ *moveServer, w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "too many pending", http.StatusServiceUnavailable)
}

func TestRun_MoveTriesTheNextAddressOnARefusal(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	refuser := startMoveServer(t, ca, refuse)
	b := startMoveServer(t, ca, func(s *moveServer, w http.ResponseWriter, r *http.Request) { bindAndHold(s, w, r) })
	a := startMoveServer(t, ca, moveThenHold(t, []string{refuser.addr, b.addr}))
	c := newMoveClient(t, a.addr, ca, tunneltest.Logger())
	ctx, cancel := context.WithCancel(context.Background())
	done := runResult(ctx, c)
	waitSignal(t, a.bound, "the bind on the first node")
	waitSignal(t, b.bound, "the bind on the address after the refusal")
	if n := refuser.streams.Load(); n != 1 {
		t.Fatalf("the refusing address got %d requests, want 1", n)
	}
	cancel()
	if err := waitRun(t, done, 5*time.Second); err != nil {
		t.Logf("Run after cancel: %v", err)
	}
	c.Close()
}

func TestRun_MoveFallsBackWhenEveryAddressRefuses(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	r1 := startMoveServer(t, ca, refuse)
	r2 := startMoveServer(t, ca, refuse)
	a := startMoveServer(t, ca, moveThenHold(t, []string{r1.addr, r2.addr}))
	c := newMoveClient(t, a.addr, ca, tunneltest.Logger())
	ctx, cancel := context.WithCancel(context.Background())
	done := runResult(ctx, c)
	waitSignal(t, a.bound, "the first bind")
	waitSignal(t, a.bound, "the bind on the fallback connection")
	if n := a.accepts.Load(); n != 2 {
		t.Fatalf("the fallback must open a new connection, accepted %d", n)
	}
	if r1.streams.Load() != 1 || r2.streams.Load() != 1 {
		t.Fatalf("each refusing address must be tried once, got %d and %d", r1.streams.Load(), r2.streams.Load())
	}
	cancel()
	if err := waitRun(t, done, 5*time.Second); err != nil {
		t.Logf("Run after cancel: %v", err)
	}
	c.Close()
}

func TestMoveTargets(t *testing.T) {
	t.Parallel()
	c := &Client{logger: tunneltest.Logger()}
	got := c.moveTargets([]string{"203.0.113.2:443", "[2001:db8::1]:443", "not-an-address", ":443", "203.0.113.3:", "2001:db8::1:443"})
	if want := []string{"203.0.113.2:443", "[2001:db8::1]:443"}; !slices.Equal(got, want) {
		t.Fatalf("moveTargets = %v, want %v", got, want)
	}
}

func TestMoveOptions_NonPositive(t *testing.T) {
	t.Parallel()
	for _, d := range []time.Duration{0, -time.Second} {
		if _, err := New("", "", "", "", nil, nil, nil, WithControlDialTimeout(d)); err == nil {
			t.Fatalf("WithControlDialTimeout(%s) must be rejected", d)
		}
		if _, err := New("", "", "", "", nil, nil, nil, WithMoveFallbackWait(d)); err == nil {
			t.Fatalf("WithMoveFallbackWait(%s) must be rejected", d)
		}
	}
}
