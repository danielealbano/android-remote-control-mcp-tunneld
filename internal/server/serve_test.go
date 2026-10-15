package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/logging"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/mesh"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/metrics"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/router"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/wire"
)

func serveTestCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "serve-test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"serve-test"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestServeTLS_ServesHTTP2OnPrebuiltListener(t *testing.T) {
	t.Parallel()
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := io.WriteString(w, r.Proto); err != nil {
				testLogger().Warn("test handler write failed", "err", err)
			}
		}),
		ReadHeaderTimeout: 5 * time.Second,
		Protocols:         h2Protocols(),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{serveTestCert(t)}, MinVersion: tls.VersionTLS12,
			NextProtos: h2NextProtos()},
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveTLS(ctx, srv, tls.NewListener(ln, srv.TLSConfig), testLogger(), "test") }()
	defer func() {
		cancel()
		tunneltest.CloseOrLog(t, srv)
		if err := <-done; err != nil {
			t.Errorf("serveTLS: %v", err)
		}
	}()
	tests := []struct {
		name  string
		http2 bool
		want  string
	}{
		{name: "h2 client", http2: true, want: "HTTP/2.0"},
		{name: "http/1.1 client", http2: false, want: "HTTP/1.1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var protocols http.Protocols
			protocols.SetHTTP2(tc.http2)
			protocols.SetHTTP1(!tc.http2)
			tr := &http.Transport{Protocols: &protocols,
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}}
			defer tr.CloseIdleConnections()
			resp, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Get("https://" + ln.Addr().String() + "/")
			if err != nil {
				t.Fatal(err)
			}
			defer tunneltest.CloseOrLog(t, resp.Body)
			if resp.Proto != tc.want {
				t.Fatalf("negotiated %s, want %s", resp.Proto, tc.want)
			}
		})
	}
}

// errListener is a net.Listener whose Accept always fails with a fixed error (drives serveTLS's
// error-propagation branch without a real socket).
type errListener struct{ err error }

func (l errListener) Accept() (net.Conn, error) { return nil, l.err }
func (l errListener) Close() error              { return nil }
func (l errListener) Addr() net.Addr            { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

// TestServeTLS_PropagatesNonShutdownError verifies serveTLS returns a non-shutdown Serve error (so the
// errgroup cancels), while ErrServerClosed / net.ErrClosed stay non-fatal.
func TestServeTLS_PropagatesNonShutdownError(t *testing.T) {
	boom := errors.New("permanent accept failure")
	if err := serveTLS(context.Background(), &http.Server{}, errListener{err: boom}, testLogger(), "x"); !errors.Is(err, boom) {
		t.Fatalf("a non-shutdown Serve error must propagate, got %v", err)
	}
	if err := serveTLS(context.Background(), &http.Server{}, errListener{err: net.ErrClosed}, testLogger(), "x"); err != nil {
		t.Fatalf("net.ErrClosed must be non-fatal, got %v", err)
	}
	if err := serveTLS(context.Background(), &http.Server{}, errListener{err: http.ErrServerClosed}, testLogger(), "x"); err != nil {
		t.Fatalf("http.ErrServerClosed must be non-fatal, got %v", err)
	}
}

// TestServeInternal_DrainsGracefully verifies an in-flight request survives ctx cancellation: serveTLS
// closes the listener (stops accepting) but does NOT hard-Close the server, so the in-flight handler
// completes (the ordered drain's Shutdown is what bounds it).
func TestServeInternal_DrainsGracefully(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		w.WriteHeader(http.StatusOK)
	})}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveTLS(ctx, srv, ln, testLogger(), "internal") }()

	respCh := make(chan int, 1)
	go func() {
		resp, gerr := http.Get("http://" + ln.Addr().String() + "/")
		if gerr != nil {
			testLogger().Warn("in-flight request failed", "err", gerr)
			respCh <- -1
			return
		}
		respCh <- resp.StatusCode
		tunneltest.CloseLogged(resp.Body)
	}()

	<-started
	cancel() // serveTLS closes the listener; the in-flight request MUST NOT be aborted
	close(release)
	select {
	case code := <-respCh:
		if code != http.StatusOK {
			t.Fatalf("in-flight request must complete gracefully, got %d", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("in-flight request did not complete")
	}
	if err := <-done; err != nil {
		t.Fatalf("serveTLS returned %v, want nil (net.ErrClosed is non-fatal)", err)
	}
}

type closeErrListener struct {
	net.Listener
	err error
}

func (l *closeErrListener) Close() error { return errors.Join(l.Listener.Close(), l.err) }

type closerFunc func() error

func (f closerFunc) Close() error { return f() }

func TestCloseLogged(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantLogged bool
	}{
		{name: "clean close", err: nil, wantLogged: false},
		{name: "already closed", err: &net.OpError{Op: "close", Net: "tcp", Err: net.ErrClosed}, wantLogged: false},
		{name: "unexpected close error", err: errors.New("close failed"), wantLogged: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf syncBuffer
			logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			closeLogged(logger, "probe", closerFunc(func() error { return tc.err }))
			if logged := strings.Contains(buf.String(), `msg="close failed" what=probe`); logged != tc.wantLogged {
				t.Fatalf("logged = %v, want %v; log = %q", logged, tc.wantLogged, buf.String())
			}
		})
	}
}

func TestShutdownLogged(t *testing.T) {
	tests := []struct {
		name       string
		closeErr   error
		wantLogged bool
	}{
		{name: "listener already closed is a clean shutdown", closeErr: &net.OpError{Op: "close", Net: "tcp", Err: net.ErrClosed}, wantLogged: false},
		{name: "unexpected listener close error is logged", closeErr: errors.New("close failed"), wantLogged: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			srv := &http.Server{Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), ReadHeaderTimeout: time.Second}
			served := make(chan error, 1)
			go func() { served <- srv.Serve(&closeErrListener{Listener: ln, err: tc.closeErr}) }()
			resp, err := (&http.Client{Timeout: 5 * time.Second}).Get("http://" + ln.Addr().String() + "/")
			if err != nil {
				t.Fatal(err)
			}
			if err := resp.Body.Close(); err != nil {
				t.Fatal(err)
			}
			var buf syncBuffer
			logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			shutdownLogged(ctx, logger, "probe", srv)
			if err := <-served; !errors.Is(err, http.ErrServerClosed) {
				t.Fatalf("Serve returned %v, want http.ErrServerClosed", err)
			}
			if logged := strings.Contains(buf.String(), `msg="server shutdown did not complete cleanly" which=probe`); logged != tc.wantLogged {
				t.Fatalf("logged = %v, want %v; log = %q", logged, tc.wantLogged, buf.String())
			}
		})
	}
}

func TestRegisterLogSinkErrors(t *testing.T) {
	tests := []struct {
		name       string
		logger     func(t *testing.T) *slog.Logger
		registered bool
	}{
		{name: "fan-out logger", registered: true, logger: func(t *testing.T) *slog.Logger {
			l, closeAll, err := logging.New([]string{"output=std;level=error"})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if cerr := closeAll(); cerr != nil {
					t.Errorf("close log sinks: %v", cerr)
				}
			})
			return l.With("node", "n1")
		}},
		{name: "plain logger", registered: false, logger: func(*testing.T) *slog.Logger { return testLogger() }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := metrics.NewMetrics()
			if err := registerLogSinkErrors(m, tc.logger(t)); err != nil {
				t.Fatal(err)
			}
			mfs, err := m.Registry().Gather()
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, mf := range mfs {
				found = found || mf.GetName() == "tunneld_log_sink_errors_total"
			}
			if found != tc.registered {
				t.Fatalf("tunneld_log_sink_errors_total registered = %v, want %v", found, tc.registered)
			}
		})
	}
}

func TestRegisterValkeyPool_ReportsTheClientPool(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr(), PoolSize: 50})
	t.Cleanup(func() {
		if err := rdb.Close(); err != nil {
			t.Errorf("close valkey client: %v", err)
		}
	})
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		t.Fatal(err)
	}
	m := metrics.NewMetrics()
	if err := registerValkeyPool(m, rdb); err != nil {
		t.Fatal(err)
	}
	mfs, err := m.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]float64{}
	for _, mf := range mfs {
		for _, mt := range mf.GetMetric() {
			got[mf.GetName()] = mt.GetGauge().GetValue()
		}
	}
	if got["tunneld_valkey_pool_max_connections"] != 50 {
		t.Fatalf("tunneld_valkey_pool_max_connections = %v, want 50", got["tunneld_valkey_pool_max_connections"])
	}
	if got["tunneld_valkey_pool_connections"] < 1 {
		t.Fatalf("tunneld_valkey_pool_connections = %v, want ≥ 1 after a command", got["tunneld_valkey_pool_connections"])
	}
}

type fakeNodeResolver struct {
	adv map[string]string
	err error
}

func (f fakeNodeResolver) LookupNode(_ context.Context, nodeID string) (string, bool, error) {
	if f.err != nil {
		return "", false, f.err
	}
	a, ok := f.adv[nodeID]
	return a, ok, nil
}

type meshCall struct {
	peer string
	req  mesh.ControlRequest
}

type fakeMeshControl struct {
	mu       sync.Mutex
	calls    []meshCall
	applied  map[string]bool
	errs     map[string]error
	block    chan struct{}
	inflight atomic.Int32
	maxSeen  atomic.Int32
	returned atomic.Int32
}

func (f *fakeMeshControl) Control(ctx context.Context, peer string, req mesh.ControlRequest) (mesh.ControlResponse, error) {
	n := f.inflight.Add(1)
	defer f.inflight.Add(-1)
	defer f.returned.Add(1)
	for {
		m := f.maxSeen.Load()
		if n <= m || f.maxSeen.CompareAndSwap(m, n) {
			break
		}
	}
	f.mu.Lock()
	f.calls = append(f.calls, meshCall{peer: peer, req: req})
	applied, err := f.applied[peer], f.errs[peer]
	f.mu.Unlock()
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return mesh.ControlResponse{}, ctx.Err()
		}
	}
	if err != nil {
		return mesh.ControlResponse{}, err
	}
	return mesh.ControlResponse{Applied: applied}, nil
}

func (f *fakeMeshControl) snapshot() []meshCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]meshCall(nil), f.calls...)
}

type fakeLiveNodes struct {
	nodes map[string]router.NodeInfo
	err   error
}

func (f fakeLiveNodes) LiveNodes(context.Context) (map[string]router.NodeInfo, error) {
	return f.nodes, f.err
}

var testOpen = wire.OpenPayload{Addr: "203.0.113.10:443", UseHTTPS: true, UseMTLS: true}

func TestOpenAdapter_LocalOwnerSendsOpen(t *testing.T) {
	ph := &fakePhoneControl{order: new(int)}
	mc := &fakeMeshControl{}
	a := &openAdapter{nodeID: "nodeA", phones: ph, nodes: fakeNodeResolver{}, mesh: mc, open: testOpen}
	if err := a.Open(context.Background(), "nodeA", "t", "conn-1", "TOKEN"); err != nil {
		t.Fatal(err)
	}
	want := testOpen
	want.Token = "TOKEN"
	if ph.openName != "t" || ph.openConnID != "conn-1" || ph.openPayload != want {
		t.Fatalf("SendOpen got (%q, %q, %+v), want (t, conn-1, %+v)", ph.openName, ph.openConnID, ph.openPayload, want)
	}
	if len(mc.snapshot()) != 0 {
		t.Fatal("a local owner must not use the mesh")
	}
}

func TestOpenAdapter_RemoteOwnerUsesMeshOpen(t *testing.T) {
	ph := &fakePhoneControl{order: new(int)}
	mc := &fakeMeshControl{applied: map[string]bool{"10.0.0.2:9443": true}}
	a := &openAdapter{nodeID: "nodeA", phones: ph, nodes: fakeNodeResolver{adv: map[string]string{"nodeB": "10.0.0.2:9443"}}, mesh: mc, open: testOpen}
	if err := a.Open(context.Background(), "nodeB", "t", "conn-1", "TOKEN"); err != nil {
		t.Fatal(err)
	}
	calls := mc.snapshot()
	want := testOpen
	want.Token = "TOKEN"
	if len(calls) != 1 || calls[0].peer != "10.0.0.2:9443" || calls[0].req.Op != "open" || calls[0].req.Tunnel != "t" ||
		calls[0].req.ConnID != "conn-1" || calls[0].req.Open == nil || *calls[0].req.Open != want {
		t.Fatalf("mesh calls = %+v, want one open to the owner's advertise address", calls)
	}
	if ph.openName != "" {
		t.Fatal("a remote owner must not be sent a local OPEN")
	}
}

func TestOpenAdapter_Failures(t *testing.T) {
	errLookup := errors.New("valkey down")
	errMesh := errors.New("peer unreachable")
	errLocal := errors.New("queue failed")
	tests := []struct {
		name    string
		owner   string
		nodes   fakeNodeResolver
		mc      *fakeMeshControl
		local   error
		wantErr error
	}{
		{name: "not applied", owner: "nodeB", nodes: fakeNodeResolver{adv: map[string]string{"nodeB": "p"}}, mc: &fakeMeshControl{}, wantErr: errOpenNotApplied},
		{name: "unregistered owner", owner: "nodeB", nodes: fakeNodeResolver{adv: map[string]string{}}, mc: &fakeMeshControl{}, wantErr: errOpenNotApplied},
		{name: "lookup error", owner: "nodeB", nodes: fakeNodeResolver{err: errLookup}, mc: &fakeMeshControl{}, wantErr: errLookup},
		{name: "mesh error", owner: "nodeB", nodes: fakeNodeResolver{adv: map[string]string{"nodeB": "p"}}, mc: &fakeMeshControl{errs: map[string]error{"p": errMesh}}, wantErr: errMesh},
		{name: "local error", owner: "nodeA", nodes: fakeNodeResolver{}, mc: &fakeMeshControl{}, local: errLocal, wantErr: errLocal},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ph := &fakePhoneControl{order: new(int), openErr: tc.local}
			a := &openAdapter{nodeID: "nodeA", phones: ph, nodes: tc.nodes, mesh: tc.mc, open: testOpen}
			if err := a.Open(context.Background(), tc.owner, "t", "conn-1", "TOKEN"); !errors.Is(err, tc.wantErr) {
				t.Fatalf("Open = %v, want it to wrap %v", err, tc.wantErr)
			}
		})
	}
}

type evictCall struct{ name, connID, reason string }

func newTestEvictor(t *testing.T, nodes liveNodeLister, mc meshControl, logger *slog.Logger) (*spliceEvictor, *[]evictCall, *sync.Mutex) {
	t.Helper()
	var mu sync.Mutex
	var calls []evictCall
	s := newSpliceEvictor("nodeA", nodes, mc, logger)
	s.local = func(name, connID, reason string) bool {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, evictCall{name: name, connID: connID, reason: reason})
		return true
	}
	return s, &calls, &mu
}

func TestSpliceEvictor_EvictsLocallyAndBroadcasts(t *testing.T) {
	nodes := map[string]router.NodeInfo{"nodeA": {Advertise: "a:9443"}, "nodeB": {Advertise: "b:9443"}, "nodeC": {Advertise: "c:9443"}}
	mc := &fakeMeshControl{}
	s, calls, mu := newTestEvictor(t, fakeLiveNodes{nodes: nodes}, mc, testLogger())
	s.PhoneConnClosed(context.Background(), "t", "conn-1", store.CloseBanEvict)
	mu.Lock()
	local := append([]evictCall(nil), *calls...)
	mu.Unlock()
	if len(local) != 1 || local[0] != (evictCall{name: "t", connID: "conn-1", reason: store.CloseBanEvict}) {
		t.Fatalf("local evictions = %+v, want one synchronous (t, conn-1, ban-evict)", local)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.Drain(ctx)
	peers := map[string]bool{}
	for _, c := range mc.snapshot() {
		if c.req.Op != "evict" || c.req.Tunnel != "t" || c.req.ConnID != "conn-1" || c.req.Reason != store.CloseBanEvict {
			t.Fatalf("broadcast request = %+v", c.req)
		}
		peers[c.peer] = true
	}
	if len(peers) != 2 || !peers["b:9443"] || !peers["c:9443"] || peers["a:9443"] {
		t.Fatalf("evict sent to %v, want every other node and never self", peers)
	}

	buf := &syncBuffer{}
	s2, calls2, mu2 := newTestEvictor(t, fakeLiveNodes{err: errors.New("valkey down")}, &fakeMeshControl{}, slog.New(slog.NewTextHandler(buf, nil)))
	s2.PhoneConnClosed(context.Background(), "t", "conn-2", store.ClosePhoneClose)
	s2.Drain(ctx)
	mu2.Lock()
	n := len(*calls2)
	mu2.Unlock()
	if n != 1 {
		t.Fatal("a node-listing failure must not skip the local eviction")
	}
	if !strings.Contains(buf.String(), "node listing failed") {
		t.Fatalf("the node-listing failure must be logged; log = %q", buf.String())
	}
}

func TestSpliceEvictor_AfterDrainOnlyEvictsLocally(t *testing.T) {
	buf := &syncBuffer{}
	mc := &fakeMeshControl{}
	s, calls, mu := newTestEvictor(t, fakeLiveNodes{nodes: map[string]router.NodeInfo{"nodeB": {Advertise: "b:9443"}}}, mc, slog.New(slog.NewTextHandler(buf, nil)))
	s.Drain(context.Background())
	s.PhoneConnClosed(context.Background(), "t", "conn-1", store.CloseServerShutdown)
	mu.Lock()
	n := len(*calls)
	mu.Unlock()
	if n != 1 {
		t.Fatal("a close after the drain started must still evict locally")
	}
	if len(mc.snapshot()) != 0 {
		t.Fatal("a close after the drain started must not broadcast")
	}
	if !strings.Contains(buf.String(), "node is draining") {
		t.Fatalf("the skipped broadcast must be logged; log = %q", buf.String())
	}
}

func TestSpliceEvictor_ConcurrencyBounded(t *testing.T) {
	mc := &fakeMeshControl{block: make(chan struct{})}
	s, _, _ := newTestEvictor(t, fakeLiveNodes{nodes: map[string]router.NodeInfo{"nodeB": {Advertise: "b:9443"}}}, mc, testLogger())
	for i := range 2 * evictBroadcastConcurrency {
		s.PhoneConnClosed(context.Background(), "t", fmt.Sprintf("conn-%d", i), store.ClosePhoneClose)
	}
	deadline := time.Now().Add(5 * time.Second)
	for mc.inflight.Load() < evictBroadcastConcurrency {
		if time.Now().After(deadline) {
			t.Fatalf("only %d broadcasts started", mc.inflight.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	if got := mc.maxSeen.Load(); got > evictBroadcastConcurrency {
		t.Fatalf("%d broadcasts in flight, want at most %d", got, evictBroadcastConcurrency)
	}
	close(mc.block)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.Drain(ctx)
	if got := len(mc.snapshot()); got != 2*evictBroadcastConcurrency {
		t.Fatalf("broadcasts sent = %d, want %d", got, 2*evictBroadcastConcurrency)
	}
	if got := mc.maxSeen.Load(); got > evictBroadcastConcurrency {
		t.Fatalf("%d broadcasts in flight, want at most %d", got, evictBroadcastConcurrency)
	}
}

func TestSpliceEvictor_BroadcastIsAsyncAndDrained(t *testing.T) {
	mc := &fakeMeshControl{block: make(chan struct{})}
	s, _, _ := newTestEvictor(t, fakeLiveNodes{nodes: map[string]router.NodeInfo{"nodeB": {Advertise: "b:9443"}}}, mc, testLogger())
	s.PhoneConnClosed(context.Background(), "t", "conn-1", store.ClosePhoneClose)
	deadline := time.Now().Add(5 * time.Second)
	for mc.inflight.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the broadcast never started")
		}
		time.Sleep(5 * time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	s.Drain(ctx)
	if elapsed := time.Since(start); elapsed < 150*time.Millisecond || elapsed > 2*time.Second {
		t.Fatalf("Drain must return shortly after its deadline, took %s", elapsed)
	}
	if mc.inflight.Load() != 0 || mc.returned.Load() != 1 {
		t.Fatalf("the drain must cancel and join the broadcast: inflight=%d returned=%d", mc.inflight.Load(), mc.returned.Load())
	}
}

func TestBroadcastControl(t *testing.T) {
	buf := &syncBuffer{}
	mc := &fakeMeshControl{
		block:   make(chan struct{}),
		applied: map[string]bool{"b:9443": false, "c:9443": true},
		errs:    map[string]error{"d:9443": errors.New("peer unreachable")},
	}
	nodes := map[string]router.NodeInfo{
		"nodeA": {Advertise: "a:9443"}, "nodeB": {Advertise: "b:9443"}, "nodeC": {Advertise: "c:9443"}, "nodeD": {Advertise: "d:9443"},
	}
	type result struct {
		applied bool
		failed  map[string]bool
	}
	done := make(chan result, 1)
	go func() {
		applied, failed := broadcastControl(context.Background(), "nodeA", nodes, mc, mesh.ControlRequest{Op: "terminate", Tunnel: "t"}, slog.New(slog.NewTextHandler(buf, nil)))
		done <- result{applied: applied, failed: failed}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for mc.inflight.Load() < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("only %d calls in flight at once, want all 3 in parallel", mc.inflight.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
	close(mc.block)
	r := <-done
	applied, failed := r.applied, r.failed
	if !applied {
		t.Fatal("applied must be the OR of the replies")
	}
	if len(failed) != 1 || !failed["nodeD"] {
		t.Fatalf("failed = %v, want nodeD", failed)
	}
	for _, c := range mc.snapshot() {
		if c.peer == "a:9443" {
			t.Fatal("broadcastControl must skip self")
		}
	}
	if got := len(mc.snapshot()); got != 3 {
		t.Fatalf("calls = %d, want 3", got)
	}
	if !strings.Contains(buf.String(), "node=nodeD") {
		t.Fatalf("the failed node must be logged; log = %q", buf.String())
	}
}

func TestControlClientAuth(t *testing.T) {
	if got := controlClientAuth(true); got != tls.RequireAndVerifyClientCert {
		t.Fatalf("mTLS dial-backs: ClientAuth = %v", got)
	}
	if got := controlClientAuth(false); got != tls.VerifyClientCertIfGiven {
		t.Fatalf("no mTLS dial-backs: ClientAuth = %v", got)
	}
}

type fakeCertLookup map[string]bool

func (f fakeCertLookup) has(host string) bool { return f[host] }

func TestDialBackReadiness(t *testing.T) {
	tests := []struct {
		name  string
		https bool
		certs fakeCertLookup
		want  bool
	}{
		{name: "plain dial-backs need no certificate", https: false, certs: fakeCertLookup{}, want: true},
		{name: "https without the control-host certificate", https: true, certs: fakeCertLookup{"enroll.example.test": true}, want: false},
		{name: "https with the control-host certificate", https: true, certs: fakeCertLookup{"connect.example.test": true}, want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := dialBackReadiness{https: tc.https, host: "connect.example.test", certs: tc.certs}
			if got := r.DialBackReady(); got != tc.want {
				t.Fatalf("DialBackReady() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestReservedCerts_Has(t *testing.T) {
	rh := &reservedHost{host: "connect.example.test"}
	rc := &reservedCerts{hosts: map[string]*reservedHost{rh.host: rh}}
	if rc.has(rh.host) {
		t.Fatal("a host without a loaded certificate must report false")
	}
	rh.cur.Store(&tls.Certificate{})
	if !rc.has(rh.host) || rc.has("unknown.example.test") {
		t.Fatal("has must report a loaded certificate for its host only")
	}
}
