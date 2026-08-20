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
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/ca"
)

func meshCert(t *testing.T, mesh bool) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	subj := pkix.Name{CommonName: "nodeA"}
	if mesh {
		subj.OrganizationalUnit = []string{ca.MeshRoleOU}
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: subj,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	c, _ := x509.ParseCertificate(der)
	return c
}

type fakeBridge struct {
	called   bool
	openErr  error
	closeNow bool
}

func (f *fakeBridge) OpenMesh(_ context.Context, tunnel, streamID string) (io.ReadWriteCloser, error) {
	f.called = true
	if f.openErr != nil {
		return nil, f.openErr
	}
	return nopRWC{}, nil
}

func (f *fakeBridge) SpliceMesh(ds, client io.ReadWriteCloser) {
	if f.closeNow {
		_ = client.Close() // signal done so the handler returns
	} else {
		go func() { time.Sleep(10 * time.Millisecond); _ = client.Close() }()
	}
}

// nopRWC is a stand-in phone dial-back stream (OpenMesh's return) for the mesh handler tests.
type nopRWC struct{}

func (nopRWC) Read([]byte) (int, error)    { return 0, io.EOF }
func (nopRWC) Write(p []byte) (int, error) { return len(p), nil }
func (nopRWC) Close() error                { return nil }

// fakeController is a func-backed mesh.Controller for the /api/v1/mesh/control tests: it records the call and
// returns the configured (nudged, err).
type fakeController struct {
	called bool
	tunnel string
	nudged bool
	err    error
}

func (f *fakeController) Renew(_ context.Context, tunnel string) (bool, error) {
	f.called = true
	f.tunnel = tunnel
	return f.nudged, f.err
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
	h := NewHandler(func(_, _ string) bool { return true }, &fakeBridge{closeNow: true}, &fakeController{})
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
	w := reqWithCert(t, meshCert(t, false), "/mesh", nil)
	if w.Code != 403 {
		t.Errorf("identity-role cert should be forbidden, got %d", w.Code)
	}
}

func TestMeshRejectsNoCert(t *testing.T) {
	w := reqWithCert(t, nil, "/mesh", nil)
	if w.Code != 403 {
		t.Errorf("no cert should be forbidden, got %d", w.Code)
	}
}

func TestMeshRejectsMissingHeaders(t *testing.T) {
	w := reqWithCert(t, meshCert(t, true), "/api/v1/mesh/data", nil)
	if w.Code != 400 {
		t.Errorf("missing headers should be 400, got %d", w.Code)
	}
}

// TestMesh_NonPostIs405 covers the frozen wire contract (docs/PROTOCOL.md §5): a mesh data stream is a
// POST /api/v1/mesh/data; a GET with a valid mesh-role cert is refused 405.
func TestMesh_NonPostIs405(t *testing.T) {
	h := NewHandler(func(_, _ string) bool { return true }, &fakeBridge{closeNow: true}, &fakeController{})
	r := httptest.NewRequest("GET", "https://node/api/v1/mesh/data", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{meshCert(t, true)}}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 405 {
		t.Fatalf("GET /api/v1/mesh/data must be 405, got %d", w.Code)
	}
}

func TestMeshNotOwner(t *testing.T) {
	h := NewHandler(func(_, _ string) bool { return false }, &fakeBridge{}, &fakeController{})
	r := httptest.NewRequest("POST", "https://node/api/v1/mesh/data", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{meshCert(t, true)}}
	r.Header.Set("X-Tunnel", "t")
	r.Header.Set("X-Conn-Id", "c")
	r.Header.Set("X-Stream-Id", "s")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 409 {
		t.Errorf("connID mismatch should be 409 (not owner), got %d", w.Code)
	}
}

func TestMeshBridgesValidStream(t *testing.T) {
	fb := &fakeBridge{closeNow: true}
	h := NewHandler(func(_, _ string) bool { return true }, fb, &fakeController{})
	r := httptest.NewRequest("POST", "https://node/api/v1/mesh/data", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{meshCert(t, true)}}
	r.Header.Set("X-Tunnel", "t")
	r.Header.Set("X-Conn-Id", "c")
	r.Header.Set("X-Stream-Id", "s")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || !fb.called {
		t.Errorf("valid mesh stream should bridge: code=%d called=%v", w.Code, fb.called)
	}
}

// TestMeshHandler_DuplicateStreamAnswers422 covers the two-phase open: OpenMesh returning
// ErrDuplicateStream answers 422, any other open error answers 502, and success answers 200 — the
// status is picked in the open phase, before the response body commits.
func TestMeshHandler_DuplicateStreamAnswers422(t *testing.T) {
	tests := []struct {
		name     string
		openErr  error
		wantCode int
	}{
		{name: "duplicate stream → 422", openErr: ErrDuplicateStream, wantCode: http.StatusUnprocessableEntity},
		{name: "other error → 502", openErr: errors.New("dial-back failed"), wantCode: http.StatusBadGateway},
		{name: "success → 200", openErr: nil, wantCode: http.StatusOK},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fb := &fakeBridge{openErr: tc.openErr, closeNow: true}
			h := NewHandler(func(_, _ string) bool { return true }, fb, &fakeController{})
			r := httptest.NewRequest("POST", "https://node/api/v1/mesh/data", nil)
			r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{meshCert(t, true)}}
			r.Header.Set("X-Tunnel", "t")
			r.Header.Set("X-Conn-Id", "c")
			r.Header.Set("X-Stream-Id", "s")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.wantCode {
				t.Fatalf("code = %d, want %d", w.Code, tc.wantCode)
			}
		})
	}
}

// TestDataPathRenamed covers the mesh split: the opaque splice serves at POST /api/v1/mesh/data, and the old
// POST /mesh path no longer exists (404).
func TestDataPathRenamed(t *testing.T) {
	h := NewHandler(func(_, _ string) bool { return true }, &fakeBridge{closeNow: true}, &fakeController{})

	r := meshRoleReq(t, "POST", "/api/v1/mesh/data", nil)
	r.Header.Set("X-Tunnel", "t")
	r.Header.Set("X-Conn-Id", "c")
	r.Header.Set("X-Stream-Id", "s")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("POST /api/v1/mesh/data must still splice (200), got %d", w.Code)
	}

	old := meshRoleReq(t, "POST", "/mesh", nil)
	wOld := httptest.NewRecorder()
	h.ServeHTTP(wOld, old)
	if wOld.Code != 404 {
		t.Fatalf("the old POST /mesh path must be gone (404), got %d", wOld.Code)
	}
}

// TestControlRenewDispatches covers the /api/v1/mesh/control renew op: a mesh-role POST {op:"renew",tunnel:"t"}
// invokes the controller and returns {nudged:true}.
func TestControlRenewDispatches(t *testing.T) {
	fc := &fakeController{nudged: true}
	h := NewHandler(func(_, _ string) bool { return true }, &fakeBridge{}, fc)
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
	if !resp.Nudged {
		t.Errorf("response nudged = false, want true")
	}
	if !fc.called || fc.tunnel != "t" {
		t.Errorf("controller called=%v tunnel=%q, want called=true tunnel=%q", fc.called, fc.tunnel, "t")
	}
}

// TestControlUnknownOp covers an unrecognized op → 400 without touching the controller.
func TestControlUnknownOp(t *testing.T) {
	fc := &fakeController{}
	h := NewHandler(func(_, _ string) bool { return true }, &fakeBridge{}, fc)
	body, _ := json.Marshal(ControlRequest{Op: "bogus", Tunnel: "t"})
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
	h := NewHandler(func(_, _ string) bool { return true }, &fakeBridge{}, fc)
	body, _ := json.Marshal(ControlRequest{Op: "renew", Tunnel: ""})
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
	h := NewHandler(func(_, _ string) bool { return true }, &fakeBridge{}, &fakeController{})
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

// TestControlClient_Errors covers Client.Control: it decodes {nudged} on a 200 and returns an error on a
// non-200 mesh response.
func TestControlClient_Errors(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		wantErr    bool
		wantNudged bool
	}{
		{name: "200 decodes nudged", status: http.StatusOK, wantErr: false, wantNudged: true},
		{name: "502 errors", status: http.StatusBadGateway, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tc.status == http.StatusOK {
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(ControlResponse{Nudged: true})
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
			if resp.Nudged != tc.wantNudged {
				t.Errorf("nudged = %v, want %v", resp.Nudged, tc.wantNudged)
			}
		})
	}
}

// TestMeshClient_Maps422ToDuplicateStream covers the client status mapping: 422 → ErrDuplicateStream,
// 409 → ErrNoOwner.
func TestMeshClient_Maps422ToDuplicateStream(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		wantErr error
	}{
		{name: "422 → duplicate stream", status: http.StatusUnprocessableEntity, wantErr: ErrDuplicateStream},
		{name: "409 → no owner", status: http.StatusConflict, wantErr: ErrNoOwner},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
			}))
			ts.EnableHTTP2 = true
			ts.StartTLS()
			defer ts.Close()
			peer := strings.TrimPrefix(ts.URL, "https://")
			c := NewClient(func() *tls.Config {
				return &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2"}, InsecureSkipVerify: true}
			}, 1)
			_, err := c.OpenStream(context.Background(), peer, "t", "conn", "s1")
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("status %d: err = %v, want %v", tc.status, err, tc.wantErr)
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
	go func() { _ = c.Run(ctx, 20*time.Millisecond) }()

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

// TestOpenStreamUnblocksOnDeadPeer covers the mesh PING health: a peer that completes the TLS
// handshake but never speaks HTTP/2 must not pin OpenStream forever — the transport's read-idle PING
// health kills the dead connection and the dial errors out within the configured bounds.
func TestOpenStreamUnblocksOnDeadPeer(t *testing.T) {
	ln, err := tls.Listen("tcp", "127.0.0.1:0", selfSignedServerTLS(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			// Complete the handshake, then read-and-discard forever, never writing a byte.
			go func() {
				buf := make([]byte, 4096)
				for {
					if _, rerr := conn.Read(buf); rerr != nil {
						_ = conn.Close()
						return
					}
				}
			}()
		}
	}()

	c := NewClient(func() *tls.Config {
		return &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2"}, InsecureSkipVerify: true}
	}, 1, WithHealthTimeouts(150*time.Millisecond, 150*time.Millisecond, time.Second))

	start := time.Now()
	_, err = c.OpenStream(context.Background(), ln.Addr().String(), "t", "conn", "s1")
	if err == nil {
		t.Fatal("a dead peer must error the dial, not hang")
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("PING health did not unblock the dial in time (took %s)", elapsed)
	}
}

// meshBlockingWriter blocks every Write (holding ownerStream.mu) until release is closed, and signals
// via entered once the first Write is in progress.
type meshBlockingWriter struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *meshBlockingWriter) Write(p []byte) (int, error) {
	b.once.Do(func() { close(b.entered) })
	<-b.release
	return len(p), nil
}

// TestOwnerStream_CloseUnblocksBlockedWrite proves, on the mesh owner side, that a Write blocked inside the
// response writer (holding o.mu) must be released by Close via the unblock hook, so Close never deadlocks.
func TestOwnerStream_CloseUnblocksBlockedWrite(t *testing.T) {
	bw := &meshBlockingWriter{entered: make(chan struct{}), release: make(chan struct{})}
	os := &ownerStream{
		w:       bw,
		done:    make(chan struct{}),
		unblock: func() { close(bw.release) },
	}

	writeReturned := make(chan struct{})
	go func() {
		_, _ = os.Write([]byte("hello"))
		close(writeReturned)
	}()
	<-bw.entered // the Write now holds o.mu, blocked in the writer

	closeReturned := make(chan struct{})
	go func() {
		_ = os.Close()
		close(closeReturned)
	}()

	select {
	case <-closeReturned:
	case <-time.After(2 * time.Second):
		t.Fatal("Close deadlocked: unblock did not release the mutex-holding Write")
	}
	select {
	case <-writeReturned:
	case <-time.After(time.Second):
		t.Fatal("the blocked Write was not released by unblock")
	}
}

// TestClient_ReapSkipsActivePools proves a pool that is idle by lastUse but still carries an active
// stream (active>0) survives the reaper, and is reaped on the first tick after the stream closes.
func TestClient_ReapSkipsActivePools(t *testing.T) {
	c := NewClient(func() *tls.Config { return &tls.Config{MinVersion: tls.VersionTLS12} }, 1)
	p := c.pool("10.0.0.9:9443") // active == 1 (simulating an open stream)
	p.lastUse.Store(0)           // force the pool to look idle so only `active` protects it

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.Run(ctx, 20*time.Millisecond) }()

	// With active==1 the pool must survive many reap ticks.
	time.Sleep(200 * time.Millisecond)
	c.mu.Lock()
	n := len(c.pools)
	c.mu.Unlock()
	if n != 1 {
		t.Fatalf("a pool with an active stream must not be reaped, pools=%d", n)
	}

	p.active.Add(-1) // the stream closes
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
	t.Fatal("an idle pool must be reaped once its active streams close")
}

// TestClient_OpenStreamErrorDecrementsActive proves a failed OpenStream must not leak the active
// count it took in pool(), or the pool would never be reaped.
func TestClient_OpenStreamErrorDecrementsActive(t *testing.T) {
	c := NewClient(func() *tls.Config {
		return &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2"}, InsecureSkipVerify: true}
	}, 1, WithHealthTimeouts(150*time.Millisecond, 150*time.Millisecond, 200*time.Millisecond))

	const peer = "127.0.0.1:1" // nothing listening → the dial fails
	if _, err := c.OpenStream(context.Background(), peer, "t", "conn", "s1"); err == nil {
		t.Fatal("a dial to a closed port must fail")
	}
	c.mu.Lock()
	p := c.pools[peer]
	c.mu.Unlock()
	if p == nil {
		t.Fatal("the pool must exist after the attempt")
	}
	if got := p.active.Load(); got != 0 {
		t.Fatalf("active after a failed OpenStream = %d, want 0", got)
	}
}
