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
func startEnrollServer(t *testing.T, ca *testCA, issueFail ...func() bool) (string, *countingListener) {
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
		if len(issueFail) > 0 && issueFail[0]() {
			w.WriteHeader(http.StatusServiceUnavailable)
			writeJSON(w, errorResponse{Reason: "acme_rate_limited", Retryable: true, RetryAfter: 1})
			return
		}
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

	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
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

// TestFetchNonce_BadHostReturnsError verifies a malformed enroll host returns an error instead of a
// nil-pointer panic (the request-construction error is now checked).
func TestFetchNonce_BadHostReturnsError(t *testing.T) {
	if _, err := FetchIssueNonce(context.Background(), "127.0.0.1:1", "bad host", nil); err == nil {
		t.Fatal("a malformed enroll host must return an error, not panic")
	}
}

// TestEnroll_Phase2FailureReturnsBootstrapIdentity verifies a retryable /issue failure returns the
// Phase-1 bootstrap identity (name + identity cert, no public cert) alongside the error, so the caller
// can retry without re-enrolling (which would orphan the name).
func TestEnroll_Phase2FailureReturnsBootstrapIdentity(t *testing.T) {
	ca := newTestCA(t)
	dialAddr, _ := startEnrollServer(t, ca, func() bool { return true }) // /issue always 503
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	id, err := Enroll(ctx, dialAddr, testEnrollHost, testControlHost, testTunnelDomain, ca.pool)
	if err == nil {
		t.Fatal("a Phase-2 /issue failure must return an error")
	}
	if id == nil || id.Name != testName || len(id.IdentityCertPEM) == 0 {
		t.Fatalf("the bootstrap identity must be returned on Phase-2 failure, got %+v", id)
	}
	if len(id.PublicCertPEM) != 0 {
		t.Error("the bootstrap identity must NOT carry a public cert yet")
	}
	var ee *EnrollError
	if !errors.As(err, &ee) || ee.Status != http.StatusServiceUnavailable {
		t.Fatalf("expected a 503 EnrollError, got %v", err)
	}
}

// TestFetchIssueNonce_RetryPathCompletes drives the documented retry path: a failed Phase-2 issue →
// bootstrap identity → fresh nonce → Renew over the SAME mTLS identity completes the issuance.
func TestFetchIssueNonce_RetryPathCompletes(t *testing.T) {
	ca := newTestCA(t)
	var issueCalls atomic.Int32
	dialAddr, _ := startEnrollServer(t, ca, func() bool { return issueCalls.Add(1) == 1 }) // fail the first /issue only
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	boot, err := Enroll(ctx, dialAddr, testEnrollHost, testControlHost, testTunnelDomain, ca.pool)
	if err == nil {
		t.Fatal("the first /issue must fail")
	}
	if boot == nil || boot.Name == "" || len(boot.PublicCertPEM) != 0 {
		t.Fatalf("Enroll must return the bootstrap identity (no public cert), got %+v", boot)
	}

	nonce, err := FetchIssueNonce(ctx, dialAddr, testEnrollHost, ca.pool)
	if err != nil {
		t.Fatalf("FetchIssueNonce: %v", err)
	}
	c, err := New(dialAddr, testControlHost, testTunnelDomain, ca.pool, boot, func(io.ReadWriteCloser) {})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Renew(ctx, nonce); err != nil {
		t.Fatalf("Renew (retry) must complete after a fresh nonce: %v", err)
	}
}

// truncatedRT returns a response whose body errors partway through Read.
type truncatedRT struct{}

func (truncatedRT) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Body: io.NopCloser(&truncReader{})}, nil
}

type truncReader struct{ done bool }

func (r *truncReader) Read(p []byte) (int, error) {
	if !r.done {
		r.done = true
		if len(p) > 0 {
			p[0] = 'x'
		}
		return 1, nil
	}
	return 0, io.ErrUnexpectedEOF
}

// TestReadResponse_TruncatedBodyErrors verifies a truncated response body surfaces a read error, not a
// misleading decode/empty-reason error.
func TestReadResponse_TruncatedBodyErrors(t *testing.T) {
	hc := &http.Client{Transport: truncatedRT{}}
	if _, err := fetchNonce(context.Background(), hc, testEnrollHost); err == nil {
		t.Fatal("a truncated response body must surface a read error")
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
