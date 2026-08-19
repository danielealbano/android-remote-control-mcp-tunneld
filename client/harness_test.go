package client

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"golang.org/x/net/http2"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/phoneconn"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/router"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

const testControlHost = "connect.example.test"
const testTunnelDomain = "example.test"
const testName = "abcdef23456x"

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert: cert, key: key, pool: pool}
}

// signLeaf signs a leaf cert (server or client) for pub with the given CN + optional SANs.
func (ca *testCA) signLeaf(t *testing.T, cn string, pub crypto.PublicKey, server bool, dns []string) []byte {
	t.Helper()
	eku := x509.ExtKeyUsageClientAuth
	if server {
		eku = x509.ExtKeyUsageServerAuth
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn}, DNSNames: dns,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{eku}, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func keyPEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// testServer is an in-process phone control plane (real phoneconn.Handler over h2/mTLS) plus the fakes
// needed to drive it.
type testServer struct {
	ca      *testCA
	mgr     *phoneconn.Manager
	store   *tunneltest.Store
	dialAdr string
	conns   *countingListener
}

func startTestServer(t *testing.T) *testServer {
	t.Helper()
	ca := newTestCA(t)
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	st := tunneltest.NewStore()
	reg := router.NewRegistry(rdb, 30*time.Second)
	mgr := phoneconn.NewManager(phoneconn.Config{
		Router: reg, Logs: st, Recorder: &tunneltest.Recorder{},
		NodeID: "node-test", NodeHost: "host-test", NodeStart: "start", RouteTTL: 30 * time.Second,
	})

	// onIssue signs a fresh identity cert (from the identity CSR) and a public cert (from the TLS CSR,
	// SAN = <name>.<tunnel-domain>) — the mTLS certificate-generation endpoint for initial + renewal.
	onIssue := func(_ context.Context, name, _, _ string, req phoneconn.IssueRequest) (phoneconn.IssueResponse, *phoneconn.IssueError) {
		idBlock, _ := pem.Decode([]byte(req.IdentityCSR))
		if idBlock == nil {
			return phoneconn.IssueResponse{}, &phoneconn.IssueError{Reason: "bad_identity_csr"}
		}
		idCSR, err := x509.ParseCertificateRequest(idBlock.Bytes)
		if err != nil {
			return phoneconn.IssueResponse{}, &phoneconn.IssueError{Reason: "bad_identity_csr"}
		}
		tlsBlock, _ := pem.Decode([]byte(req.TLSCSR))
		if tlsBlock == nil {
			return phoneconn.IssueResponse{}, &phoneconn.IssueError{Reason: "bad_tls_csr"}
		}
		tlsCSR, err := x509.ParseCertificateRequest(tlsBlock.Bytes)
		if err != nil {
			return phoneconn.IssueResponse{}, &phoneconn.IssueError{Reason: "bad_tls_csr"}
		}
		fqdn := name + "." + testTunnelDomain
		idCert := ca.signLeaf(t, name, idCSR.PublicKey, false, nil)
		pubCert := ca.signLeaf(t, fqdn, tlsCSR.PublicKey, true, []string{fqdn})
		return phoneconn.IssueResponse{IdentityCert: string(idCert), PublicCert: string(pubCert), CA: "test"}, nil
	}

	handler := phoneconn.NewHandler(phoneconn.HandlerConfig{
		Manager:      mgr,
		ValidName:    func(n string) bool { return n == testName },
		BanTunnel:    func(string, string) bool { return false },
		PingInterval: time.Hour, StreamPending: 64, OnIssue: onIssue,
	})

	// Server cert for the control host.
	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srvCertPEM := ca.signLeaf(t, testControlHost, &srvKey.PublicKey, true, []string{testControlHost})
	srvCert, err := tls.X509KeyPair(srvCertPEM, keyPEM(t, srvKey))
	if err != nil {
		t.Fatal(err)
	}
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{srvCert}, ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: ca.pool, MinVersion: tls.VersionTLS12,
	}
	srv := &http.Server{Handler: handler, TLSConfig: tlsConf}
	if err := http2.ConfigureServer(srv, &http2.Server{}); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cl := &countingListener{Listener: ln}
	go func() { _ = srv.Serve(tls.NewListener(cl, srv.TLSConfig)) }()
	t.Cleanup(func() { _ = srv.Close() })

	return &testServer{ca: ca, mgr: mgr, store: st, dialAdr: ln.Addr().String(), conns: cl}
}

// newClient builds a client with a fresh identity signed by the test CA, wired to backend.
func (ts *testServer) newClient(t *testing.T, backend Backend) *Client {
	t.Helper()
	idKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	idCertPEM := ts.ca.signLeaf(t, testName, &idKey.PublicKey, false, nil)
	ident := &Identity{Name: testName, IdentityCertPEM: idCertPEM, IdentityKey: idKey, CA: "test"}
	c, err := New(ts.dialAdr, testControlHost, testTunnelDomain, ts.ca.pool, ident, backend)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func waitFor(t *testing.T, d time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}
