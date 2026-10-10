package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type h2TestServer struct {
	addr    string
	pool    *x509.CertPool
	accepts atomic.Int64
	mu      sync.Mutex
	conns   []net.Conn
}

type trackingListener struct {
	net.Listener
	s *h2TestServer
}

func (l *trackingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.s.accepts.Add(1)
	l.s.mu.Lock()
	l.s.conns = append(l.s.conns, c)
	l.s.mu.Unlock()
	return c, nil
}

func (s *h2TestServer) closeConns() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.conns {
		_ = c.Close()
	}
	s.conns = nil
}

func startH2TestServer(t *testing.T, nextProtos []string, maxStreams int, handler http.Handler) *h2TestServer {
	t.Helper()
	ca := newTestCA(t)
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
	s := &h2TestServer{addr: ln.Addr().String(), pool: ca.pool}
	tlsConf := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, NextProtos: nextProtos}
	srv := &http.Server{Handler: handler, TLSConfig: tlsConf, ReadHeaderTimeout: 5 * time.Second,
		HTTP2: &http.HTTP2Config{MaxConcurrentStreams: maxStreams}}
	go func() { _ = srv.Serve(tls.NewListener(&trackingListener{Listener: ln, s: s}, tlsConf)) }()
	t.Cleanup(func() { _ = srv.Close() })
	return s
}

func noClientCert() *tls.Certificate { return &tls.Certificate{} }

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
}

func getOnce(hc *http.Client) (*http.Response, error) {
	resp, err := hc.Get("https://" + testControlHost + "/")
	if err != nil {
		return nil, err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp, nil
}

func TestNewMTLSTransport_RejectsNonH2Server(t *testing.T) {
	t.Parallel()
	s := startH2TestServer(t, nil, 0, okHandler())
	tr := newMTLSTransport(s.addr, testControlHost, s.pool, noClientCert)
	defer tr.CloseIdleConnections()
	_, err := getOnce(&http.Client{Transport: tr, Timeout: 5 * time.Second})
	if !errors.Is(err, errNotHTTP2) {
		t.Fatalf("want errNotHTTP2, got %v", err)
	}
}

func TestNewMTLSTransport_OneConnForConcurrentColdRequests(t *testing.T) {
	t.Parallel()
	s := startH2TestServer(t, []string{"h2", "http/1.1"}, 0, okHandler())
	tr := newMTLSTransport(s.addr, testControlHost, s.pool, noClientCert)
	defer tr.CloseIdleConnections()
	hc := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			resp, err := getOnce(hc)
			if err == nil && resp.ProtoMajor != 2 {
				err = errors.New("response not served over HTTP/2: " + resp.Proto)
			}
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := s.accepts.Load(); got != 1 {
		t.Fatalf("want 1 TCP connection for 8 concurrent cold requests, got %d", got)
	}
}

func TestNewMTLSTransport_OpensSecondConnWhenStreamsSaturated(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	held := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	s := startH2TestServer(t, []string{"h2", "http/1.1"}, 2, held)
	tr := newMTLSTransport(s.addr, testControlHost, s.pool, noClientCert)
	defer tr.CloseIdleConnections()
	hc := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	resps := make([]*http.Response, 0, 3)
	defer func() {
		close(release)
		for _, r := range resps {
			_, _ = io.Copy(io.Discard, r.Body)
			_ = r.Body.Close()
		}
	}()
	for i := range 3 {
		resp, err := hc.Get("https://" + testControlHost + "/")
		if err != nil {
			t.Fatalf("stream %d: %v", i+1, err)
		}
		resps = append(resps, resp)
	}
	if got := s.accepts.Load(); got != 2 {
		t.Fatalf("want a 2nd TCP connection once the first is saturated (2 streams), got %d", got)
	}
}

func TestNewMTLSTransport_ReconnectsAfterConnDrop(t *testing.T) {
	t.Parallel()
	s := startH2TestServer(t, []string{"h2", "http/1.1"}, 0, okHandler())
	tr := newMTLSTransport(s.addr, testControlHost, s.pool, noClientCert)
	defer tr.CloseIdleConnections()
	hc := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	if _, err := getOnce(hc); err != nil {
		t.Fatal(err)
	}
	s.closeConns()
	if !waitFor(t, 5*time.Second, func() bool { _, err := getOnce(hc); return err == nil }) {
		t.Fatal("a request must succeed on a new connection after the drop")
	}
	if got := s.accepts.Load(); got != 2 {
		t.Fatalf("want exactly 2 TCP connections (original + reconnect), got %d", got)
	}
}

// TestControlConnectBindAndDuplex covers: control connect + bind, dial-back opens a data stream, and a
// full-duplex splice (the echo backend proves interleaved read/write works across the data stream).
func TestControlConnectBindAndDuplex(t *testing.T) {
	ts := startTestServer(t)
	echo := func(s io.ReadWriteCloser) { _, _ = io.Copy(s, s) }
	c := ts.newClient(t, echo)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.Run(ctx) }()

	// The control stream must bind the route (HasConn becomes true).
	if !waitFor(t, 3*time.Second, func() bool { return ts.mgr.HasConn(testName) }) {
		t.Fatal("control connect must bind the route")
	}

	// Dial-back: OpenStream sends OPEN, the client opens the /api/v1/data stream, deliverStream returns it.
	openCtx, openCancel := context.WithTimeout(ctx, 3*time.Second)
	defer openCancel()
	ds, err := ts.mgr.OpenStream(openCtx, testName, "stream-1")
	if err != nil {
		t.Fatalf("dial-back OpenStream failed: %v", err)
	}
	defer func() { _ = ds.Close() }()

	// Full-duplex echo: write client→phone bytes; the echo backend must send them back phone→client.
	msg := []byte("full-duplex-hello")
	if _, err := ds.Write(msg); err != nil {
		t.Fatalf("write to data stream: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(ds, buf); err != nil {
		t.Fatalf("read echo from data stream: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("echo mismatch: got %q want %q", buf, msg)
	}
}

// TestRenewViaNudgeAndIssue covers the renewal flow: RENEW_NUDGE{nonce} on the control stream → the client
// calls the mTLS POST /api/v1/issue endpoint → the server regenerates the identity + public certs → the client
// swaps in the rotated identity (both certs change).
func TestRenewViaNudgeAndIssue(t *testing.T) {
	ts := startTestServer(t)
	c := ts.newClient(t, func(io.ReadWriteCloser) {})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.Run(ctx) }()

	if !waitFor(t, 3*time.Second, func() bool { return ts.mgr.HasConn(testName) }) {
		t.Fatal("control must bind before renewal")
	}
	originalID := string(c.Identity().IdentityCertPEM)

	if !ts.mgr.SendRenewNudge(testName, "00112233", "") {
		t.Fatal("SendRenewNudge should reach the live connection")
	}

	if !waitFor(t, 5*time.Second, func() bool {
		id := c.Identity()
		return string(id.IdentityCertPEM) != originalID && len(id.PublicCertPEM) > 0
	}) {
		t.Fatal("renewal must call /api/v1/issue and swap in the regenerated identity + public certs")
	}
}
