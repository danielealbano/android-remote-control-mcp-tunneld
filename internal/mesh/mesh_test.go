package mesh

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net/http/httptest"
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
	closeNow bool
}

func (f *fakeBridge) BridgeMesh(_ context.Context, tunnel, streamID string, client io.ReadWriteCloser) error {
	f.called = true
	if f.closeNow {
		_ = client.Close() // signal done so the handler returns
	} else {
		go func() { time.Sleep(10 * time.Millisecond); _ = client.Close() }()
	}
	return nil
}

func reqWithCert(t *testing.T, cert *x509.Certificate, path string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	h := NewHandler(func(_, _ string) bool { return true }, &fakeBridge{closeNow: true})
	r := httptest.NewRequest("POST", "https://node/"+path, nil)
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
	w := reqWithCert(t, meshCert(t, false), "mesh", nil)
	if w.Code != 403 {
		t.Errorf("identity-role cert should be forbidden, got %d", w.Code)
	}
}

func TestMeshRejectsNoCert(t *testing.T) {
	w := reqWithCert(t, nil, "mesh", nil)
	if w.Code != 403 {
		t.Errorf("no cert should be forbidden, got %d", w.Code)
	}
}

func TestMeshRejectsMissingHeaders(t *testing.T) {
	w := reqWithCert(t, meshCert(t, true), "mesh", nil)
	if w.Code != 400 {
		t.Errorf("missing headers should be 400, got %d", w.Code)
	}
}

func TestMeshNotOwner(t *testing.T) {
	h := NewHandler(func(_, _ string) bool { return false }, &fakeBridge{})
	r := httptest.NewRequest("POST", "https://node/mesh", nil)
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
	h := NewHandler(func(_, _ string) bool { return true }, fb)
	r := httptest.NewRequest("POST", "https://node/mesh", nil)
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
	_ = c.pool("10.0.0.5:9443")
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
