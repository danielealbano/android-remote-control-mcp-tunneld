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
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

func writeJSON(w http.ResponseWriter, v any) {
	if err := json.NewEncoder(w).Encode(v); err != nil {
		tunneltest.Logger().Warn("test enroll server response write failed", "err", err)
	}
}

func readJSON(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
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

type enrollServerOpts struct {
	issueFail  func() *errorResponse
	enrollFail func() *errorResponse

	mu           sync.Mutex
	issueNonces  []string
	enrollNonces []string
}

func (o *enrollServerOpts) nonces() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return slices.Clone(o.issueNonces)
}

func (o *enrollServerOpts) phase1Nonces() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return slices.Clone(o.enrollNonces)
}

func writeInjectedError(w http.ResponseWriter, e *errorResponse) {
	status := http.StatusBadRequest
	if e.Retryable {
		status = http.StatusServiceUnavailable
	}
	w.WriteHeader(status)
	writeJSON(w, *e)
}

// startEnrollServer stands up a minimal two-phase enrollment endpoint (GET /api/v1/enroll/nonce, POST /api/v1/enroll
// server-TLS, POST /api/v1/issue mTLS) signing everything with ca. It serves both HTTP/1.1 (Phase-1) and HTTP/2
// (Phase-2 mTLS) via ALPN and returns the dial address plus the connection-counting listener.
func startEnrollServer(t *testing.T, ca *testCA, opts ...*enrollServerOpts) (string, *countingListener) {
	t.Helper()
	o := &enrollServerOpts{}
	if len(opts) > 0 {
		o = opts[0]
	}
	var nonceSeq atomic.Int64

	signFromCSR := func(w http.ResponseWriter, kind, csrPEM, cn string, server bool, dns []string) (string, bool) {
		csr, err := parseCSR(csrPEM)
		if err != nil {
			tunneltest.Logger().Warn("test enroll server: unparseable CSR", "err", err)
			http.Error(w, "bad "+kind+" csr", http.StatusBadRequest)
			return "", false
		}
		certPEM, err := ca.sign(cn, csr.PublicKey, server, dns)
		if err != nil {
			tunneltest.Logger().Error("test enroll server: signing failed", "err", err)
			http.Error(w, "signing failed", http.StatusInternalServerError)
			return "", false
		}
		return string(certPEM), true
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/enroll/nonce", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, nonceResponse{Nonce: fmt.Sprintf("%02x", nonceSeq.Add(1))})
	})
	mux.HandleFunc("/api/v1/enroll", func(w http.ResponseWriter, r *http.Request) {
		var body enrollRequestBody
		if err := readJSON(r, &body); err != nil {
			tunneltest.Logger().Warn("test enroll server: undecodable body", "err", err)
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		o.mu.Lock()
		o.enrollNonces = append(o.enrollNonces, body.Nonce)
		o.mu.Unlock()
		if o.enrollFail != nil {
			if e := o.enrollFail(); e != nil {
				writeInjectedError(w, e)
				return
			}
		}
		idCert, ok := signFromCSR(w, "identity", body.IdentityCSR, testName, false, nil)
		if !ok {
			return
		}
		writeJSON(w, enrollResponse{Name: testName, IdentityCert: idCert, IssueNonce: "bb"})
	})
	mux.HandleFunc("/api/v1/issue", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "mtls required", http.StatusUnauthorized)
			return
		}
		var body issueRequestBody
		if err := readJSON(r, &body); err != nil {
			tunneltest.Logger().Warn("test enroll server: undecodable body", "err", err)
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		o.mu.Lock()
		o.issueNonces = append(o.issueNonces, body.Nonce)
		o.mu.Unlock()
		if o.issueFail != nil {
			if e := o.issueFail(); e != nil {
				writeInjectedError(w, e)
				return
			}
		}
		idCert, ok := signFromCSR(w, "identity", body.IdentityCSR, testName, false, nil)
		if !ok {
			return
		}
		fqdn := testName + "." + testTunnelDomain
		pubCert, ok := signFromCSR(w, "tls", body.TLSCSR, fqdn, true, []string{fqdn})
		if !ok {
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
		ClientAuth:   tls.VerifyClientCertIfGiven, // /api/v1/enroll presents no cert; /api/v1/issue does (checked in-handler)
		ClientCAs:    ca.pool,
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}
	srv := &http.Server{Handler: mux, TLSConfig: tlsConf}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cl := &countingListener{Listener: ln}
	tunneltest.ServeHTTP(t, srv, tls.NewListener(cl, srv.TLSConfig))
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

// TestEnroll_Phase2FailureReturnsBootstrapIdentity verifies a /api/v1/issue failure returns the
// Phase-1 bootstrap identity (name + identity cert, no public cert) alongside the error.
func TestEnroll_Phase2FailureReturnsBootstrapIdentity(t *testing.T) {
	ca := newTestCA(t)
	opts := &enrollServerOpts{issueFail: func() *errorResponse { return &errorResponse{Reason: "acme_failed"} }}
	dialAddr, _ := startEnrollServer(t, ca, opts)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var slept []time.Duration
	sleep := func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil }
	id, err := enroll(ctx, sleep, dialAddr, testEnrollHost, testControlHost, testTunnelDomain, ca.pool)
	if err == nil {
		t.Fatal("a Phase-2 /api/v1/issue failure must return an error")
	}
	if id == nil || id.Name != testName || len(id.IdentityCertPEM) == 0 {
		t.Fatalf("the bootstrap identity must be returned on Phase-2 failure, got %+v", id)
	}
	if len(id.PublicCertPEM) != 0 {
		t.Error("the bootstrap identity must NOT carry a public cert yet")
	}
	var ee *EnrollError
	if !errors.As(err, &ee) || ee.Status != http.StatusBadRequest || ee.Retryable {
		t.Fatalf("expected a non-retryable 400 EnrollError, got %v", err)
	}
	if len(slept) != 0 || len(opts.nonces()) != 1 {
		t.Fatalf("a non-retryable failure must stop at once: slept %v, issue requests %v", slept, opts.nonces())
	}
}

func TestFetchIssueNonce_RetryPathCompletes(t *testing.T) {
	ca := newTestCA(t)
	var issueCalls atomic.Int32
	opts := &enrollServerOpts{issueFail: func() *errorResponse {
		if issueCalls.Add(1) == 1 {
			return &errorResponse{Reason: "acme_rate_limited", Retryable: true, RetryAfter: 1}
		}
		return nil
	}}
	dialAddr, _ := startEnrollServer(t, ca, opts)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sleep := func(context.Context, time.Duration) error { return nil }

	id, err := enroll(ctx, sleep, dialAddr, testEnrollHost, testControlHost, testTunnelDomain, ca.pool)
	if err != nil {
		t.Fatalf("the retry must complete the issuance: %v", err)
	}
	if len(id.PublicCertPEM) == 0 {
		t.Fatal("the retried issuance must return the public cert")
	}
	nonces := opts.nonces()
	if len(nonces) != 2 || nonces[0] == nonces[1] {
		t.Fatalf("issue nonces = %v, want the Phase-1 issue nonce then a freshly fetched one", nonces)
	}
}

func TestFetchNonce_ErrorClasses(t *testing.T) {
	answer := func(status int, body string) *http.Client {
		return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
		})}
	}
	tests := []struct {
		name          string
		hc            *http.Client
		wantEnroll    bool
		wantTransport bool
		wantWait      time.Duration
		wantRetry     bool
	}{
		{name: "retryable refusal", hc: answer(http.StatusServiceUnavailable, `{"reason":"internal","retryable":true,"retry_after_seconds":3}`),
			wantEnroll: true, wantWait: 3 * time.Second, wantRetry: true},
		{name: "final refusal", hc: answer(http.StatusBadRequest, `{"reason":"bad_request"}`), wantEnroll: true},
		{name: "network failure", hc: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errInjected })},
			wantTransport: true, wantWait: 5 * time.Second, wantRetry: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := fetchNonce(context.Background(), tc.hc, testEnrollHost)
			_, isEnroll := errors.AsType[*EnrollError](err)
			_, isTransport := errors.AsType[*transportError](err)
			if isEnroll != tc.wantEnroll || isTransport != tc.wantTransport {
				t.Fatalf("fetchNonce = %v (EnrollError %v, transportError %v), want %v / %v", err, isEnroll, isTransport, tc.wantEnroll, tc.wantTransport)
			}
			if wait, retry := issueRetryWait(err, 0); retry != tc.wantRetry || wait != tc.wantWait {
				t.Fatalf("issueRetryWait = %s, %v; want %s, %v", wait, retry, tc.wantWait, tc.wantRetry)
			}
		})
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
	_, err := fetchNonce(context.Background(), hc, testEnrollHost)
	// It must surface the READ error, not a decode error: assert the wrapped io.ErrUnexpectedEOF (a
	// bare err != nil would also pass against the pre-fix code, which misreported it as a decode error).
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("a truncated body must surface the read error (io.ErrUnexpectedEOF), got %v", err)
	}
}

// TestClient_CloseReleasesControlTransport proves Client.Close releases the control transport's pooled
// connection once Run has returned.
func TestClient_CloseReleasesControlTransport(t *testing.T) {
	ts := startTestServer(t)
	c := ts.newClient(t, func(io.ReadWriteCloser) {})

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		if err := c.Run(ctx); err != nil && ctx.Err() == nil {
			tunneltest.Logger().Warn("client run failed", "err", err)
		}
	}()

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

func TestErrorFromResponse(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantReason string
		wantRetry  bool
		wantAfter  time.Duration
		wantDecode bool
	}{
		{name: "structured error", body: `{"reason":"enroll_rate","retryable":true,"retry_after_seconds":30}`,
			wantReason: "enroll_rate", wantRetry: true, wantAfter: 30 * time.Second},
		{name: "undecodable body", body: "<html>bad gateway</html>", wantDecode: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := errorFromResponse(http.StatusBadGateway, []byte(tc.body))
			var ee *EnrollError
			if !errors.As(err, &ee) || ee.Status != http.StatusBadGateway || ee.Reason != tc.wantReason {
				t.Fatalf("errorFromResponse = %v, want an *EnrollError with status 502 and reason %q", err, tc.wantReason)
			}
			if ee.Retryable != tc.wantRetry || ee.RetryAfter != tc.wantAfter {
				t.Fatalf("retryable=%v retryAfter=%s, want %v %s", ee.Retryable, ee.RetryAfter, tc.wantRetry, tc.wantAfter)
			}
			if decodeFailed := strings.Contains(err.Error(), "decode error response"); decodeFailed != tc.wantDecode {
				t.Fatalf("decode failure surfaced = %v, want %v (err %v)", decodeFailed, tc.wantDecode, err)
			}
		})
	}
}

func TestClient_ResponseCloseErrorsReturned(t *testing.T) {
	ctx := context.Background()
	hc := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: failingBody{strings.NewReader(`{"nonce":"aa"}`)}, Request: r}, nil
	})}
	tests := []struct {
		name string
		call func() error
		want string
	}{
		{name: "nonce fetch", want: "enroll: close nonce response", call: func() error {
			_, err := fetchNonce(ctx, hc, testEnrollHost)
			return err
		}},
		{name: "phase-1 enroll", want: "enroll: close response", call: func() error {
			_, err := postEnroll(ctx, hc, testEnrollHost, []byte("{}"))
			return err
		}},
		{name: "issuance", want: "issue: close response", call: func() error {
			_, err := issueCerts(ctx, hc, testControlHost, testName, testTunnelDomain, "", "00")
			return err
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(); !errors.Is(err, errInjected) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want the %q body close error", err, tc.want)
			}
		})
	}
}
