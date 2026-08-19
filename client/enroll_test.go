package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func writeJSON(w http.ResponseWriter, v any) {
	_ = json.NewEncoder(w).Encode(v)
}

func readJSON(r *http.Request, v any) bool {
	return json.NewDecoder(r.Body).Decode(v) == nil
}

const testEnrollHost = "enroll.example.test"

// countingListener wraps a net.Listener and tracks how many accepted connections are still open, so a
// test can assert a client released its pooled TLS connections.
type countingListener struct {
	net.Listener
	live atomic.Int64
}

func (l *countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.live.Add(1)
	return &countingConn{Conn: c, parent: l}, nil
}

type countingConn struct {
	net.Conn
	parent *countingListener
	once   sync.Once
}

func (c *countingConn) Close() error {
	c.once.Do(func() { c.parent.live.Add(-1) })
	return c.Conn.Close()
}

// startEnrollServer stands up a minimal two-phase enrollment endpoint (GET /enroll/nonce, POST /enroll
// server-TLS, POST /issue mTLS) signing everything with ca. It serves both HTTP/1.1 (Phase-1) and HTTP/2
// (Phase-2 mTLS) via ALPN and returns the dial address plus the connection-counting listener.
func startEnrollServer(t *testing.T, ca *testCA) (string, *countingListener) {
	t.Helper()

	signFromCSR := func(csrPEM, cn string, server bool, dns []string) (string, bool) {
		csr, err := parseCSR(csrPEM)
		if err != nil {
			return "", false
		}
		return string(ca.signLeaf(t, cn, csr.PublicKey, server, dns)), true
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/enroll/nonce", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, nonceResponse{Nonce: "aa"})
	})
	mux.HandleFunc("/enroll", func(w http.ResponseWriter, r *http.Request) {
		var body enrollRequestBody
		if !readJSON(r, &body) {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		idCert, ok := signFromCSR(body.IdentityCSR, testName, false, nil)
		if !ok {
			http.Error(w, "bad identity csr", http.StatusBadRequest)
			return
		}
		writeJSON(w, enrollResponse{Name: testName, IdentityCert: idCert, IssueNonce: "bb"})
	})
	mux.HandleFunc("/issue", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "mtls required", http.StatusUnauthorized)
			return
		}
		var body issueRequestBody
		if !readJSON(r, &body) {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		idCert, ok := signFromCSR(body.IdentityCSR, testName, false, nil)
		if !ok {
			http.Error(w, "bad identity csr", http.StatusBadRequest)
			return
		}
		fqdn := testName + "." + testTunnelDomain
		pubCert, ok := signFromCSR(body.TLSCSR, fqdn, true, []string{fqdn})
		if !ok {
			http.Error(w, "bad tls csr", http.StatusBadRequest)
			return
		}
		writeJSON(w, issueResponseBody{IdentityCert: idCert, PublicCert: pubCert, CA: "test"})
	})

	srvKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srvCertPEM := ca.signLeaf(t, testEnrollHost, &srvKey.PublicKey, true, []string{testEnrollHost, testControlHost})
	srvCert, err := tls.X509KeyPair(srvCertPEM, keyPEM(t, srvKey))
	if err != nil {
		t.Fatal(err)
	}
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{srvCert},
		ClientAuth:   tls.VerifyClientCertIfGiven, // /enroll presents no cert; /issue does (checked in-handler)
		ClientCAs:    ca.pool,
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}
	srv := &http.Server{Handler: mux, TLSConfig: tlsConf}
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
	return ln.Addr().String(), cl
}

func parseCSR(csrPEM string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return nil, errors.New("client: no PEM block in CSR")
	}
	return x509.ParseCertificateRequest(block.Bytes)
}

// TestEnroll_ClosesTransports proves Enroll releases both of its transports (Phase-1 server-TLS and
// Phase-2 mTLS): once Enroll returns, no accepted server connection stays open.
func TestEnroll_ClosesTransports(t *testing.T) {
	ca := newTestCA(t)
	dialAddr, cl := startEnrollServer(t, ca)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	id, err := Enroll(ctx, dialAddr, testEnrollHost, testControlHost, testTunnelDomain, ca.pool)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if id == nil || id.Name == "" || len(id.PublicCertPEM) == 0 {
		t.Fatal("Enroll returned an incomplete identity")
	}
	if !waitFor(t, 3*time.Second, func() bool { return cl.live.Load() == 0 }) {
		t.Fatalf("Enroll left %d connection(s) open; transports were not closed", cl.live.Load())
	}
}

// TestClient_CloseReleasesControlTransport proves Client.Close releases the control transport's pooled
// connection once Run has returned.
func TestClient_CloseReleasesControlTransport(t *testing.T) {
	ts := startTestServer(t)
	c := ts.newClient(t, func(io.ReadWriteCloser) {})

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() { defer close(runDone); _ = c.Run(ctx) }()

	if !waitFor(t, 3*time.Second, func() bool { return ts.mgr.HasConn(testName) }) {
		t.Fatal("control connect must bind the route")
	}
	if ts.conns.live.Load() == 0 {
		t.Fatal("expected a live control connection while Run is active")
	}

	cancel()
	<-runDone // Close's contract: call once Run has returned
	// The transport marks the conn idle asynchronously after the canceled streams unwind; poll
	// Close until the pool has quiesced and released it.
	if !waitFor(t, 3*time.Second, func() bool { c.Close(); return ts.conns.live.Load() == 0 }) {
		t.Fatalf("Close must release the control transport; %d connection(s) remain", ts.conns.live.Load())
	}
}
