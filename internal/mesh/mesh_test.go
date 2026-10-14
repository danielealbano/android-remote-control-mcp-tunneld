package mesh

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/ca"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/wire"
)

func meshCert(t *testing.T, mesh bool) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	subj := pkix.Name{CommonName: "nodeA"}
	if mesh {
		subj.OrganizationalUnit = []string{ca.MeshRoleOU}
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: subj,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// fakeController is a func-backed mesh.Controller for the /api/v1/mesh/control tests: it records the call
// and returns the configured result.
type fakeController struct {
	called     bool
	tunnel     string
	connID     string
	reason     string
	open       wire.OpenPayload
	nudged     bool
	terminated bool
	opened     bool
	evicted    bool
	err        error
}

func (f *fakeController) Renew(_ context.Context, tunnel string) (bool, error) {
	f.called = true
	f.tunnel = tunnel
	return f.nudged, f.err
}

func (f *fakeController) Terminate(_ context.Context, tunnel string) (bool, error) {
	f.called = true
	f.tunnel = tunnel
	return f.terminated, f.err
}

func (f *fakeController) Open(_ context.Context, tunnel, connID string, open wire.OpenPayload) (bool, error) {
	f.called = true
	f.tunnel, f.connID, f.open = tunnel, connID, open
	return f.opened, f.err
}

func (f *fakeController) Evict(_ context.Context, tunnel, connID, reason string) (bool, error) {
	f.called = true
	f.tunnel, f.connID, f.reason = tunnel, connID, reason
	return f.evicted, f.err
}

// meshRoleReq builds a mesh-role-authenticated request to https://node/<path> with an optional JSON body.
func meshRoleReq(t *testing.T, method, path string, body []byte) *http.Request {
	t.Helper()
	var b io.Reader
	if body != nil {
		b = bytes.NewReader(body)
	}
	r := httptest.NewRequest(method, "https://node"+path, b)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{meshCert(t, true)}}
	return r
}

func reqWithCert(t *testing.T, cert *x509.Certificate, path string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	h := newTestHandler(t, &fakeController{})
	r := httptest.NewRequest("POST", "https://node"+path, nil)
	if cert != nil {
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestMeshRejectsIdentityRoleCert(t *testing.T) {
	w := reqWithCert(t, meshCert(t, false), "/api/v1/mesh/control", nil)
	if w.Code != 403 {
		t.Errorf("identity-role cert should be forbidden, got %d", w.Code)
	}
}

func TestMeshRejectsNoCert(t *testing.T) {
	w := reqWithCert(t, nil, "/api/v1/mesh/control", nil)
	if w.Code != 403 {
		t.Errorf("no cert should be forbidden, got %d", w.Code)
	}
}

// TestControlRenewDispatches covers the /api/v1/mesh/control renew op: a mesh-role POST {op:"renew",tunnel:"t"}
// invokes the controller and returns {applied:true}.
func TestControlRenewDispatches(t *testing.T) {
	fc := &fakeController{nudged: true}
	h := newTestHandler(t, fc)
	body, err := json.Marshal(ControlRequest{Op: "renew", Tunnel: "t"})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, meshRoleReq(t, "POST", "/api/v1/mesh/control", body))
	if w.Code != 200 {
		t.Fatalf("renew must be 200, got %d", w.Code)
	}
	var resp ControlResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Applied {
		t.Errorf("response applied = false, want true")
	}
	if !fc.called || fc.tunnel != "t" {
		t.Errorf("controller called=%v tunnel=%q, want called=true tunnel=%q", fc.called, fc.tunnel, "t")
	}
}

// TestControlTerminateDispatches covers the /api/v1/mesh/control terminate op: a mesh-role POST
// {op:"terminate",tunnel:"t"} invokes the controller and returns {applied:true}.
func TestControlTerminateDispatches(t *testing.T) {
	fc := &fakeController{terminated: true}
	h := newTestHandler(t, fc)
	body, err := json.Marshal(ControlRequest{Op: "terminate", Tunnel: "t"})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, meshRoleReq(t, "POST", "/api/v1/mesh/control", body))
	if w.Code != 200 {
		t.Fatalf("terminate must be 200, got %d", w.Code)
	}
	var resp ControlResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Applied {
		t.Errorf("response applied = false, want true")
	}
	if !fc.called || fc.tunnel != "t" {
		t.Errorf("controller called=%v tunnel=%q, want called=true tunnel=%q", fc.called, fc.tunnel, "t")
	}
}

func TestControlOpenDispatches(t *testing.T) {
	fc := &fakeController{opened: true}
	h := newTestHandler(t, fc)
	open := wire.OpenPayload{Token: "TOKEN", Addr: "203.0.113.10:443", UseHTTPS: true, UseMTLS: true}
	body, err := json.Marshal(ControlRequest{Op: "open", Tunnel: "t", ConnID: "c1", Open: &open})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, meshRoleReq(t, "POST", "/api/v1/mesh/control", body))
	if w.Code != 200 {
		t.Fatalf("open must be 200, got %d", w.Code)
	}
	var resp ControlResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Applied {
		t.Error("response applied = false, want the controller's true")
	}
	if fc.tunnel != "t" || fc.connID != "c1" || fc.open != open {
		t.Errorf("controller got tunnel=%q conn=%q open=%+v", fc.tunnel, fc.connID, fc.open)
	}
}

func TestControlEvictDispatches(t *testing.T) {
	fc := &fakeController{evicted: true}
	h := newTestHandler(t, fc)
	body, err := json.Marshal(ControlRequest{Op: "evict", Tunnel: "t", ConnID: "c1", Reason: "ban-evict"})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, meshRoleReq(t, "POST", "/api/v1/mesh/control", body))
	if w.Code != 200 {
		t.Fatalf("evict must be 200, got %d", w.Code)
	}
	var resp ControlResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Applied || fc.tunnel != "t" || fc.connID != "c1" || fc.reason != "ban-evict" {
		t.Errorf("applied=%v controller got tunnel=%q conn=%q reason=%q", resp.Applied, fc.tunnel, fc.connID, fc.reason)
	}
}

func TestControlConnIDValidation(t *testing.T) {
	full := &wire.OpenPayload{Token: "TOKEN", Addr: "203.0.113.10:443"}
	tests := []struct {
		name string
		req  ControlRequest
	}{
		{name: "open without conn_id", req: ControlRequest{Op: "open", Tunnel: "t", Open: full}},
		{name: "evict without conn_id", req: ControlRequest{Op: "evict", Tunnel: "t"}},
		{name: "open without payload", req: ControlRequest{Op: "open", Tunnel: "t", ConnID: "c1"}},
		{name: "open without token", req: ControlRequest{Op: "open", Tunnel: "t", ConnID: "c1", Open: &wire.OpenPayload{Addr: "203.0.113.10:443"}}},
		{name: "open without addr", req: ControlRequest{Op: "open", Tunnel: "t", ConnID: "c1", Open: &wire.OpenPayload{Token: "TOKEN"}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fc := &fakeController{}
			h := newTestHandler(t, fc)
			body, err := json.Marshal(tc.req)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, meshRoleReq(t, "POST", "/api/v1/mesh/control", body))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", w.Code)
			}
			if fc.called {
				t.Fatal("the controller must not be called for an invalid request")
			}
		})
	}
}

func TestMesh_DataPathGone(t *testing.T) {
	h := newTestHandler(t, &fakeController{})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, meshRoleReq(t, "POST", "/api/v1/mesh/data", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("POST /api/v1/mesh/data must be 404, got %d", w.Code)
	}
}

// TestControlUnknownOp covers an unrecognized op → 400 without touching the controller.
func TestControlUnknownOp(t *testing.T) {
	fc := &fakeController{}
	h := newTestHandler(t, fc)
	body, err := json.Marshal(ControlRequest{Op: "bogus", Tunnel: "t"})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, meshRoleReq(t, "POST", "/api/v1/mesh/control", body))
	if w.Code != 400 {
		t.Fatalf("unknown op must be 400, got %d", w.Code)
	}
	if fc.called {
		t.Error("controller must not be called for an unknown op")
	}
}

// TestControlMissingTunnel covers renew with an empty tunnel → 400 without touching the controller.
func TestControlMissingTunnel(t *testing.T) {
	fc := &fakeController{}
	h := newTestHandler(t, fc)
	body, err := json.Marshal(ControlRequest{Op: "renew", Tunnel: ""})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, meshRoleReq(t, "POST", "/api/v1/mesh/control", body))
	if w.Code != 400 {
		t.Fatalf("missing tunnel must be 400, got %d", w.Code)
	}
	if fc.called {
		t.Error("controller must not be called when the tunnel is missing")
	}
}

// TestControlNonPostIs405 covers a non-POST to /api/v1/mesh/control with a mesh-role cert → 405.
func TestControlNonPostIs405(t *testing.T) {
	h := newTestHandler(t, &fakeController{})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, meshRoleReq(t, "GET", "/api/v1/mesh/control", nil))
	if w.Code != 405 {
		t.Fatalf("GET /api/v1/mesh/control must be 405, got %d", w.Code)
	}
}

// TestControlRejectsNonMeshRole covers the mesh-role gate on the control path: a non-mesh-role cert → 403
// (the role check precedes the path switch).
func TestControlRejectsNonMeshRole(t *testing.T) {
	w := reqWithCert(t, meshCert(t, false), "/api/v1/mesh/control", nil)
	if w.Code != 403 {
		t.Errorf("non-mesh-role cert on /api/v1/mesh/control should be 403, got %d", w.Code)
	}
}

// TestControlClient_Errors covers Client.Control: it decodes {applied} on a 200 and returns an error on a
// non-200 mesh response.
func TestControlClient_Errors(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		wantErr     bool
		wantApplied bool
	}{
		{name: "200 decodes applied", status: http.StatusOK, wantErr: false, wantApplied: true},
		{name: "502 errors", status: http.StatusBadGateway, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tc.status == http.StatusOK {
					w.Header().Set("Content-Type", "application/json")
					if err := json.NewEncoder(w).Encode(ControlResponse{Applied: true}); err != nil {
						t.Errorf("encode control response: %v", err)
					}
					return
				}
				w.WriteHeader(tc.status)
			}))
			ts.EnableHTTP2 = true
			ts.StartTLS()
			defer ts.Close()
			peer := strings.TrimPrefix(ts.URL, "https://")
			c := NewClient(func() *tls.Config {
				return &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2"}, InsecureSkipVerify: true}
			}, 1)
			resp, err := c.Control(context.Background(), peer, ControlRequest{Op: "renew", Tunnel: "t"})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("status %d: want an error, got nil", tc.status)
				}
				return
			}
			if err != nil {
				t.Fatalf("status %d: unexpected error: %v", tc.status, err)
			}
			if resp.Applied != tc.wantApplied {
				t.Errorf("applied = %v, want %v", resp.Applied, tc.wantApplied)
			}
		})
	}
}

func TestClientPoolRoundRobin(t *testing.T) {
	c := NewClient(func() *tls.Config { return &tls.Config{} }, 4)
	p := c.pool("10.0.0.1:9443")
	if len(p.clients) != 4 {
		t.Errorf("pool size = %d, want 4", len(p.clients))
	}
	// Same peer returns the same pool.
	if c.pool("10.0.0.1:9443") != p {
		t.Error("pool should be memoized per peer")
	}
}

type poolRec struct {
	calls []struct {
		peer string
		size int
	}
}

func (r *poolRec) MeshPool(peer string, size int) {
	r.calls = append(r.calls, struct {
		peer string
		size int
	}{peer, size})
}

func TestClientReportsPoolSizeOnce(t *testing.T) {
	rec := &poolRec{}
	c := NewClient(func() *tls.Config { return &tls.Config{} }, 4, WithRecorder(rec))
	c.pool("10.0.0.2:9443")
	c.pool("10.0.0.2:9443") // memoized — must NOT re-report
	if len(rec.calls) != 1 {
		t.Fatalf("MeshPool calls = %d, want 1 (reported once at pool creation)", len(rec.calls))
	}
	if rec.calls[0].peer != "10.0.0.2:9443" || rec.calls[0].size != 4 {
		t.Errorf("MeshPool = (%q,%d), want (10.0.0.2:9443, 4)", rec.calls[0].peer, rec.calls[0].size)
	}
}

// TestClientReapsIdlePools covers the pool janitor: an idle per-peer pool is reaped (connections
// closed, gauge zeroed) and lazily re-created on the next use.
func TestClientReapsIdlePools(t *testing.T) {
	rec := &poolRec{}
	c := NewClient(func() *tls.Config { return &tls.Config{MinVersion: tls.VersionTLS12} }, 2, WithRecorder(rec))
	p := c.pool("10.0.0.5:9443")
	p.active.Add(-1) // pool() counted this acquisition; release it (no live stream) so the reaper can run
	if len(c.pools) != 1 {
		t.Fatal("pool must exist after first use")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		if err := c.Run(ctx, 20*time.Millisecond); err != nil && ctx.Err() == nil {
			tunneltest.Logger().Warn("mesh client run failed", "err", err)
		}
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		n := len(c.pools)
		c.mu.Unlock()
		if n == 0 {
			return // reaped
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("an idle pool must be reaped")
}

// selfSignedServerTLS builds a self-signed keypair server tls.Config for the dead-peer test.
func selfSignedServerTLS(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "dead-peer"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"dead-peer"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2"},
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{der}, PrivateKey: key,
		}},
	}
}

// TestClient_Control_UnblocksOnDeadPeer covers the mesh PING health: a peer that completes the TLS
// handshake but never speaks HTTP/2 must not pin Control forever — the transport's read-idle PING
// health kills the dead connection and the call errors out within the configured bounds.
func TestClient_Control_UnblocksOnDeadPeer(t *testing.T) {
	ln, err := tls.Listen("tcp", "127.0.0.1:0", selfSignedServerTLS(t))
	if err != nil {
		t.Fatal(err)
	}
	defer tunneltest.CloseOrLog(t, ln)
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				if !errors.Is(aerr, net.ErrClosed) {
					tunneltest.Logger().Warn("test listener accept failed", "err", aerr)
				}
				return
			}
			// Complete the handshake, then read-and-discard forever, never writing a byte.
			go func() {
				buf := make([]byte, 4096)
				for {
					if _, rerr := conn.Read(buf); rerr != nil {
						if !errors.Is(rerr, io.EOF) {
							tunneltest.Logger().Debug("test peer read ended", "err", rerr)
						}
						tunneltest.CloseLogged(conn)
						return
					}
				}
			}()
		}
	}()

	c := NewClient(func() *tls.Config {
		return &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2"}, InsecureSkipVerify: true}
	}, 1, WithHealthTimeouts(150*time.Millisecond, 150*time.Millisecond, time.Second), WithControlTimeout(time.Minute))

	start := time.Now()
	_, err = c.Control(context.Background(), ln.Addr().String(), ControlRequest{Op: "renew", Tunnel: "t"})
	if err == nil {
		t.Fatal("a dead peer must error the call, not hang")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("PING health did not unblock the call in time (took %s)", elapsed)
	}
}

// TestClient_ReapSkipsActivePools proves a pool that is idle by lastUse but still carries an in-flight
// Control call (active>0) survives the reaper, and is reaped on the first tick after the call returns.
func TestClient_ReapSkipsActivePools(t *testing.T) {
	release := make(chan struct{})
	peer := startMeshPeer(t, 0, release)
	c := NewClient(insecureMeshTLS, 1)
	callDone := make(chan error, 1)
	go func() {
		_, err := c.Control(context.Background(), peer.addr, ControlRequest{Op: "renew", Tunnel: "t"})
		callDone <- err
	}()
	waitEntered(t, peer, 1)
	c.mu.Lock()
	p := c.pools[peer.addr]
	c.mu.Unlock()
	p.lastUse.Store(0) // force the pool to look idle so only `active` protects it

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		if err := c.Run(ctx, 20*time.Millisecond); err != nil && ctx.Err() == nil {
			tunneltest.Logger().Warn("mesh client run failed", "err", err)
		}
	}()

	// With active==1 the pool must survive many reap ticks.
	time.Sleep(200 * time.Millisecond)
	c.mu.Lock()
	n := len(c.pools)
	c.mu.Unlock()
	if n != 1 {
		t.Fatalf("a pool with an in-flight call must not be reaped, pools=%d", n)
	}

	close(release)
	if err := <-callDone; err != nil {
		t.Fatal(err)
	}
	p.lastUse.Store(0)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		n := len(c.pools)
		c.mu.Unlock()
		if n == 0 {
			return // reaped once idle AND inactive
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("an idle pool must be reaped once its in-flight calls return")
}

// TestClient_ControlErrorDecrementsActive proves a failed Control must not leak the active
// count it took in pool(), or the pool would never be reaped.
func TestClient_ControlErrorDecrementsActive(t *testing.T) {
	c := NewClient(func() *tls.Config {
		return &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2"}, InsecureSkipVerify: true}
	}, 1, WithHealthTimeouts(150*time.Millisecond, 150*time.Millisecond, 200*time.Millisecond))

	const peer = "127.0.0.1:1" // nothing listening → the dial fails
	if _, err := c.Control(context.Background(), peer, ControlRequest{Op: "renew", Tunnel: "t"}); err == nil {
		t.Fatal("a dial to a closed port must fail")
	}
	c.mu.Lock()
	p := c.pools[peer]
	c.mu.Unlock()
	if p == nil {
		t.Fatal("the pool must exist after the attempt")
	}
	if got := p.active.Load(); got != 0 {
		t.Fatalf("active after a failed Control = %d, want 0", got)
	}
}

type meshPeer struct {
	addr    string
	accepts atomic.Int64
	entered atomic.Int64
	mu      sync.Mutex
	conns   []net.Conn
}

type meshPeerListener struct {
	net.Listener
	p *meshPeer
}

func (l *meshPeerListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.p.accepts.Add(1)
	l.p.mu.Lock()
	l.p.conns = append(l.p.conns, c)
	l.p.mu.Unlock()
	return c, nil
}

func (p *meshPeer) closeConns(t *testing.T) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.conns {
		tunneltest.CloseOrLog(t, c)
	}
	p.conns = nil
}

func startMeshPeer(t *testing.T, maxStreams int, release <-chan struct{}) *meshPeer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &meshPeer{addr: ln.Addr().String()}
	tlsConf := selfSignedServerTLS(t)
	srv := &http.Server{
		TLSConfig: tlsConf, ReadHeaderTimeout: 5 * time.Second,
		HTTP2: &http.HTTP2Config{MaxConcurrentStreams: maxStreams},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p.entered.Add(1)
			if release != nil {
				select {
				case <-release:
				case <-r.Context().Done():
					return
				}
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(ControlResponse{Applied: true}); err != nil {
				tunneltest.Logger().Debug("mesh peer response write ended", "err", err)
			}
		}),
	}
	tunneltest.ServeHTTP(t, srv, tls.NewListener(&meshPeerListener{Listener: ln, p: p}, tlsConf))
	return p
}

func insecureMeshTLS() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2"}, InsecureSkipVerify: true}
}

func waitEntered(t *testing.T, p *meshPeer, n int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for p.entered.Load() < n {
		if time.Now().After(deadline) {
			t.Fatalf("only %d of %d calls reached the peer", p.entered.Load(), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestClient_RejectsNonH2Peer(t *testing.T) {
	t.Parallel()
	tlsConf := selfSignedServerTLS(t)
	tlsConf.NextProtos = nil
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConf)
	if err != nil {
		t.Fatal(err)
	}
	defer tunneltest.CloseOrLog(t, ln)
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				if !errors.Is(aerr, net.ErrClosed) {
					tunneltest.Logger().Warn("test listener accept failed", "err", aerr)
				}
				return
			}
			go func() {
				buf := make([]byte, 4096)
				for {
					if _, rerr := conn.Read(buf); rerr != nil {
						if !errors.Is(rerr, io.EOF) {
							tunneltest.Logger().Debug("test peer read ended", "err", rerr)
						}
						tunneltest.CloseLogged(conn)
						return
					}
				}
			}()
		}
	}()
	c := NewClient(insecureMeshTLS, 1)
	_, err = c.Control(context.Background(), ln.Addr().String(), ControlRequest{Op: "renew", Tunnel: "t"})
	if !errors.Is(err, errPeerNotHTTP2) {
		t.Fatalf("want errPeerNotHTTP2, got %v", err)
	}
}

func TestClient_OneConnForConcurrentColdStreams(t *testing.T) {
	t.Parallel()
	p := startMeshPeer(t, 0, nil)
	c := NewClient(insecureMeshTLS, 1)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			if _, err := c.Control(context.Background(), p.addr, ControlRequest{Op: "renew", Tunnel: "t"}); err != nil {
				errs <- err
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if got := p.accepts.Load(); got != 1 {
		t.Fatalf("want 1 TCP connection for 8 concurrent cold calls, got %d", got)
	}
}

func TestClient_OpensSecondConnWhenStreamsSaturated(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	p := startMeshPeer(t, 2, release)
	c := NewClient(insecureMeshTLS, 1)
	errs := make(chan error, 3)
	for range 3 {
		go func() {
			_, err := c.Control(context.Background(), p.addr, ControlRequest{Op: "renew", Tunnel: "t"})
			errs <- err
		}()
	}
	waitEntered(t, p, 3)
	close(release)
	for range 3 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if got := p.accepts.Load(); got != 2 {
		t.Fatalf("want a 2nd TCP connection once the first is saturated (2 streams), got %d", got)
	}
}

func TestClient_ReconnectsAfterPeerConnDrop(t *testing.T) {
	t.Parallel()
	p := startMeshPeer(t, 0, nil)
	c := NewClient(insecureMeshTLS, 1)
	if _, err := c.Control(context.Background(), p.addr, ControlRequest{Op: "renew", Tunnel: "t"}); err != nil {
		t.Fatal(err)
	}
	p.closeConns(t)
	deadline := time.Now().Add(5 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, err := c.Control(ctx, p.addr, ControlRequest{Op: "renew", Tunnel: "t"})
		cancel()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no successful Control after the drop: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := p.accepts.Load(); got != 2 {
		t.Fatalf("want exactly 2 TCP connections (original + reconnect), got %d", got)
	}
}

func TestClient_Control_HonoursTimeout(t *testing.T) {
	t.Parallel()
	p := startMeshPeer(t, 0, make(chan struct{}))
	c := NewClient(insecureMeshTLS, 1, WithControlTimeout(200*time.Millisecond))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	start := time.Now()
	_, err := c.Control(ctx, p.addr, ControlRequest{Op: "renew", Tunnel: "t"})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Control = %v, want the per-request deadline", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("the per-request timeout did not bound the call (took %s)", elapsed)
	}
	if ctx.Err() != nil {
		t.Fatal("the caller ctx must still be live: the per-request timeout must fire first")
	}
}

func TestClient_NewH2ClientMapsPingTimeouts(t *testing.T) {
	t.Parallel()
	c := NewClient(insecureMeshTLS, 1, WithHealthTimeouts(3*time.Second, 7*time.Second, time.Second))
	tr, ok := c.newH2Client().Transport.(*http.Transport)
	if !ok {
		t.Fatal("the mesh client transport must be *http.Transport")
	}
	if tr.HTTP2 == nil || tr.HTTP2.SendPingTimeout != 3*time.Second || tr.HTTP2.PingTimeout != 7*time.Second {
		t.Fatalf("HTTP2 config = %+v, want SendPingTimeout=3s PingTimeout=7s", tr.HTTP2)
	}
	if tr.MaxConnsPerHost != 1 || tr.Protocols == nil || !tr.Protocols.HTTP2() || tr.Protocols.HTTP1() {
		t.Fatal("want an HTTP/2-only transport capped at one connection per host")
	}
}

func newTestHandler(t *testing.T, control Controller) *Handler {
	t.Helper()
	h, err := NewHandler(control)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestNewHandler_RejectsNilLogger(t *testing.T) {
	if _, err := NewHandler(&fakeController{}, WithHandlerLogger(nil)); err == nil {
		t.Fatal("a nil logger must be rejected")
	}
}

func TestControl_LogsFailures(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		ctrlErr  error
		wantCode int
		want     string
	}{
		{name: "malformed request", body: "{", wantCode: http.StatusBadRequest, want: `msg="mesh control request malformed"`},
		{name: "op fails", body: `{"op":"renew","tunnel":"t"}`, ctrlErr: errors.New("phone gone"), wantCode: http.StatusBadGateway,
			want: `msg="mesh control op failed" op=renew tunnel=t err="phone gone"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			h, err := NewHandler(&fakeController{err: tc.ctrlErr},
				WithHandlerLogger(slog.New(slog.NewTextHandler(&buf, nil))))
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, meshRoleReq(t, "POST", "/api/v1/mesh/control", []byte(tc.body)))
			if w.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d", w.Code, tc.wantCode)
			}
			if !strings.Contains(buf.String(), tc.want) {
				t.Fatalf("the control failure must be logged; log = %q", buf.String())
			}
		})
	}
}

type failingBody struct{ io.Reader }

func (failingBody) Close() error { return errors.New("body close failed") }

type meshRoundTrip func(*http.Request) (*http.Response, error)

func (f meshRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestClient_Control_ReturnsBodyCloseError(t *testing.T) {
	const peer = "peer.example.test:9443"
	c := NewClient(func() *tls.Config { return &tls.Config{MinVersion: tls.VersionTLS12} }, 1)
	c.pools[peer] = &peerPool{addr: peer, clients: []*http.Client{{Transport: meshRoundTrip(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: failingBody{strings.NewReader(`{"applied":true}`)}, Request: r}, nil
	})}}}
	_, err := c.Control(context.Background(), peer, ControlRequest{Op: "renew", Tunnel: "t"})
	if err == nil || !strings.Contains(err.Error(), "mesh control "+peer+": close response: body close failed") {
		t.Fatalf("Control = %v, want the body close error", err)
	}
	if got := c.pools[peer].active.Load(); got != 0 {
		t.Fatalf("Control must release the pool slot, active = %d", got)
	}
}
