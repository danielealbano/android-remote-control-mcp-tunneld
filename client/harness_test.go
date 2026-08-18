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
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/wire"
)

const testControlHost = "connect.example.test"
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
	cert, _ := x509.ParseCertificate(der)
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
	der, _ := x509.MarshalECPrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// testServer is an in-process phone control plane (real phoneconn.Handler over h2/mTLS) plus the fakes
// needed to drive it.
type testServer struct {
	ca      *testCA
	mgr     *phoneconn.Manager
	store   *tunneltest.Store
	dialAdr string
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

	// onRenew signs a fresh identity cert from the submitted CSR (realistic: cert pubkey == fresh key).
	onRenew := func(_ context.Context, name, _, _ string, sub wire.RenewSubmitPayload) (wire.CertPushPayload, error) {
		block, _ := pem.Decode([]byte(sub.IdentityCSR))
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			return wire.CertPushPayload{}, err
		}
		newCert := ca.signLeaf(t, name, csr.PublicKey, false, nil)
		return wire.CertPushPayload{IdentityCertPEM: string(newCert), PublicCertPEM: string(newCert)}, nil
	}
	challenge := func(context.Context) (string, error) { return "deadbeef", nil }

	handler := phoneconn.NewHandler(phoneconn.HandlerConfig{
		Manager:      mgr,
		ValidName:    func(n string) bool { return n == testName },
		BanTunnel:    func(string, string) bool { return false },
		PingInterval: time.Hour, StreamPending: 64, OnRenew: onRenew, Challenge: challenge,
	})

	// Server cert for the control host.
	srvKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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
	go func() { _ = srv.Serve(tls.NewListener(ln, srv.TLSConfig)) }()
	t.Cleanup(func() { _ = srv.Close() })

	return &testServer{ca: ca, mgr: mgr, store: st, dialAdr: ln.Addr().String()}
}

// newClient builds a client with a fresh identity signed by the test CA, wired to backend.
func (ts *testServer) newClient(t *testing.T, backend Backend) *Client {
	t.Helper()
	idKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	idCertPEM := ts.ca.signLeaf(t, testName, &idKey.PublicKey, false, nil)
	ident := &Identity{Name: testName, IdentityCertPEM: idCertPEM, IdentityKey: idKey, CA: "test"}
	c, err := New(ts.dialAdr, testControlHost, ts.ca.pool, ident, backend)
	if err != nil {
		t.Fatal(err)
	}
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
