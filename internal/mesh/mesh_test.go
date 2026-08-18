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
	c := NewClient(func() *tls.Config { return &tls.Config{} }, 4, 8)
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
	c := NewClient(func() *tls.Config { return &tls.Config{} }, 4, 8, WithRecorder(rec))
	c.pool("10.0.0.2:9443")
	c.pool("10.0.0.2:9443") // memoized — must NOT re-report
	if len(rec.calls) != 1 {
		t.Fatalf("MeshPool calls = %d, want 1 (reported once at pool creation)", len(rec.calls))
	}
	if rec.calls[0].peer != "10.0.0.2:9443" || rec.calls[0].size != 4 {
		t.Errorf("MeshPool = (%q,%d), want (10.0.0.2:9443, 4)", rec.calls[0].peer, rec.calls[0].size)
	}
}
