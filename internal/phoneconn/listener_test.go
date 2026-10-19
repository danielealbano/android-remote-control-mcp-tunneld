package phoneconn

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
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/ca"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/router"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/wire"
)

// flushRecorder is an httptest.ResponseRecorder that satisfies http.Flusher and tracks writes safely
// across goroutines (serveControl writes from its own goroutine in these tests).
type flushRecorder struct {
	mu sync.Mutex
	rr *httptest.ResponseRecorder
}

func newFlushRecorder() *flushRecorder { return &flushRecorder{rr: httptest.NewRecorder()} }

func (f *flushRecorder) Header() http.Header { f.mu.Lock(); defer f.mu.Unlock(); return f.rr.Header() }
func (f *flushRecorder) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rr.Write(p)
}
func (f *flushRecorder) WriteHeader(code int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rr.WriteHeader(code)
}
func (f *flushRecorder) Flush() {}

func (f *flushRecorder) code() int { f.mu.Lock(); defer f.mu.Unlock(); return f.rr.Code }

// blockedReader blocks reads until closed (a phone that sends nothing on the control stream).
type blockedReader struct {
	ch   chan struct{}
	once sync.Once
}

func newBlockedReader() *blockedReader { return &blockedReader{ch: make(chan struct{})} }
func (b *blockedReader) Read([]byte) (int, error) {
	<-b.ch
	return 0, io.EOF
}
func (b *blockedReader) close() { b.once.Do(func() { close(b.ch) }) }

func newTestHandler(t *testing.T, pending int, ping time.Duration) (*Handler, *Manager) {
	t.Helper()
	m, _, _, _ := newMgr(t)
	h := NewHandler(HandlerConfig{DialBacks: NewDialBacks(tunneltest.Logger()), Manager: m, PingInterval: ping, StreamPending: pending})
	return h, m
}

// TestServeControlReleasesPendingSlotAfterBind covers the --limit-stream-pending semantics: the
// semaphore bounds concurrent PRE-BIND handshakes only — a BOUND phone must not hold a slot, so a
// second phone binds fine with StreamPending=1.
func TestServeControlReleasesPendingSlotAfterBind(t *testing.T) {
	h, m := newTestHandler(t, 1, time.Hour)

	start := func(name string) (*blockedReader, context.CancelFunc, chan struct{}) {
		body := newBlockedReader()
		ctx, cancel := context.WithCancel(context.Background())
		req := httptest.NewRequest("GET", "/api/v1/control", body).WithContext(ctx)
		done := make(chan struct{})
		go func() {
			h.serveControl(newFlushRecorder(), req, phoneIdentity{name: name})
			close(done)
		}()
		return body, cancel, done
	}

	bodyA, cancelA, doneA := start("phonea")
	waitCond(t, func() bool { return m.HasConn("phonea") })

	// With phone A BOUND (slot released), phone B must also bind under StreamPending=1.
	bodyB, cancelB, doneB := start("phoneb")
	waitCond(t, func() bool { return m.HasConn("phoneb") })

	cancelA()
	cancelB()
	bodyA.close()
	bodyB.close()
	<-doneA
	<-doneB
}

func TestControl_NewCertificateReplacesLiveConnection(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { tunneltest.CloseOrLog(t, rdb) })
	reg, err := router.NewRegistry(rdb, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	hook := &recordingClosedHook{fr: newFakeRouter()}
	m := NewManager(Config{Router: reg, Logs: tunneltest.NewStore(), Recorder: &fakeRec{}, Closed: hook, NodeID: "nodeA",
		NodeHost: "host-a", NodeStart: "2026-10-18T00:00:00Z", RouteTTL: 30 * time.Second})
	h := NewHandler(HandlerConfig{DialBacks: NewDialBacks(tunneltest.Logger()), Manager: m, PingInterval: time.Hour, StreamPending: 4})
	const name = "abcdef234567"

	start := func(cert *x509.Certificate) (*flushRecorder, *blockedReader, context.CancelFunc, chan struct{}) {
		body := newBlockedReader()
		ctx, cancel := context.WithCancel(context.Background())
		req := httptest.NewRequest(http.MethodPost, "/api/v1/control", body).WithContext(ctx)
		req.RemoteAddr = "198.51.100.50:40000"
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
		req.ProtoMajor, req.ProtoMinor = 2, 0
		rec := newFlushRecorder()
		done := make(chan struct{})
		go func() {
			h.ServeHTTP(rec, req)
			close(done)
		}()
		return rec, body, cancel, done
	}

	_, bodyA, cancelA, doneA := start(selfSignedCert(t, name, false))
	waitCond(t, func() bool { return m.HasConn(name) })
	_, connA, ok, err := reg.LookupRoute(context.Background(), name)
	if err != nil || !ok {
		t.Fatalf("connection A must bind: ok=%v err=%v", ok, err)
	}

	recB, bodyB, cancelB, doneB := start(selfSignedCert(t, name, false))
	select {
	case <-doneA:
	case <-time.After(2 * time.Second):
		t.Fatal("a new identity certificate for the name must replace the live connection")
	}
	waitCond(t, func() bool { return recB.code() == http.StatusOK })
	cur, ok := m.lookup(name)
	if !ok {
		t.Fatal("connection B must be live")
	}
	_, routed, ok, err := reg.LookupRoute(context.Background(), name)
	if err != nil || !ok || routed != cur.connID || routed == connA {
		t.Fatalf("the route must hold B's connID %q (A was %q), got %q ok=%v err=%v", cur.connID, connA, routed, ok, err)
	}
	hook.mu.Lock()
	calls := append([]closedCall(nil), hook.calls...)
	hook.mu.Unlock()
	if want := (closedCall{name: name, connID: connA, reason: "phone-close"}); len(calls) == 0 || calls[0] != want {
		t.Fatalf("closed hook calls = %v, want first %v", calls, want)
	}

	cancelA()
	cancelB()
	bodyA.close()
	bodyB.close()
	<-doneB
}

// TestServeControlPendingCapRefuses covers the pre-bind refusal: a saturated pre-bind semaphore
// answers 503 without touching the manager.
func TestServeControlPendingCapRefuses(t *testing.T) {
	h, m := newTestHandler(t, 1, time.Hour)
	h.sem <- struct{}{} // saturate the pre-bind slot

	rec := newFlushRecorder()
	req := httptest.NewRequest("GET", "/api/v1/control", newBlockedReader())
	h.serveControl(rec, req, phoneIdentity{name: "phonec"})
	if rec.code() != 503 {
		t.Fatalf("saturated pre-bind semaphore must answer 503, got %d", rec.code())
	}
	if m.HasConn("phonec") {
		t.Fatal("a refused handshake must not register a connection")
	}
}

// TestLivenessTimeoutCloses covers the missed-PONG teardown: a phone that never PONGs is closed with
// the liveness reason after livenessMissedPings intervals.
func TestLivenessTimeoutCloses(t *testing.T) {
	h, m := newTestHandler(t, 4, 5*time.Millisecond)
	body := newBlockedReader()
	defer body.close()
	req := httptest.NewRequest("GET", "/api/v1/control", body)
	done := make(chan struct{})
	go func() {
		h.serveControl(newFlushRecorder(), req, phoneIdentity{name: "phoned"})
		close(done)
	}()
	waitCond(t, func() bool { return m.HasConn("phoned") })

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("a silent phone must be torn down by the liveness bound")
	}
	c, ok := m.lookup("phoned")
	if ok && c.closeReason() != "liveness-timeout" {
		t.Fatalf("close reason = %q, want liveness-timeout", c.closeReason())
	}
}

// TestReadPumpPongStampsLiveness covers the PONG path: a PONG frame advances lastPong; a malformed
// frame tears the connection down with protocol-error.
func TestReadPumpPongStampsLiveness(t *testing.T) {
	h, _ := newTestHandler(t, 4, time.Hour)
	c := newConn("phonee")
	before := c.lastPong.Load()

	pong, err := wire.EncodeControl(wire.CtrlPong, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.readPump(bytes.NewReader(pong), c) // EOF after the frame → phone-close
	if c.lastPong.Load() <= before {
		t.Fatal("a PONG frame must advance lastPong")
	}

	c2 := newConn("phonef")
	// A frame with an oversize length prefix is a wire-protocol violation → close reason protocol-error
	// (distinct from a graceful phone-close), so forensics can tell a misbehaving phone from a disconnect.
	bad := []byte{0x01, 0xff, 0xff, 0xff, 0xff}
	h.readPump(bytes.NewReader(bad), c2)
	if c2.closeReason() != "protocol-error" {
		t.Fatalf("close reason = %q, want protocol-error", c2.closeReason())
	}
	if !c2.isClosed() {
		t.Fatal("a malformed frame must tear the connection down")
	}
}

// TestServeHTTPIPBanFirst covers the peer-IP ban gate: a banned IP is refused BEFORE any identity
// check (no client cert present here — the ban answer must come first).
func TestServeHTTPIPBanFirst(t *testing.T) {
	m, _, _, _ := newMgr(t)
	banned := netip.MustParseAddr("198.51.100.99")
	dialBacks := NewDialBacks(tunneltest.Logger())
	h := NewHandler(HandlerConfig{DialBacks: dialBacks, Manager: m, PingInterval: time.Hour, StreamPending: 4,
		BanIP: func(a netip.Addr) bool { return a == banned }})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	registered := make(chan struct{})
	awaited := make(chan struct{})
	go func() {
		defer close(awaited)
		if _, err := dialBacks.Await(ctx, "TOKEN", "phonex", func(context.Context) error { close(registered); return nil }); !errors.Is(err, context.Canceled) {
			t.Errorf("Await = %v, want the cancellation", err)
		}
	}()
	<-registered
	dreq := httptest.NewRequest("GET", wire.DialBackPath, nil)
	dreq.RemoteAddr = "198.51.100.99:40000"
	dreq.Header.Set("Upgrade", wire.DialUpgrade)
	dreq.Header.Set(wire.DialBackHeader, "TOKEN")
	drec := httptest.NewRecorder()
	h.ServeHTTP(drec, dreq)
	if drec.Code != 403 || drec.Header().Get("Connection") != "close" {
		t.Fatalf("banned peer IP on the dial-back path = %d Connection=%q, want 403 + close", drec.Code, drec.Header().Get("Connection"))
	}
	if !dialBacks.expects("TOKEN", "") {
		t.Fatal("the ban gate must answer before any token lookup consumes the waiter")
	}
	cancel()
	<-awaited

	req := httptest.NewRequest("GET", "/api/v1/control", nil)
	req.RemoteAddr = "198.51.100.99:40000"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatalf("banned peer IP must get 403, got %d", rec.Code)
	}

	req2 := httptest.NewRequest("GET", "/api/v1/control", nil)
	req2.RemoteAddr = "198.51.100.98:40000"
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	// An unbanned IP must not hit the ban gate: decode the JSON body and assert the reason is anything
	// but "banned" (it fails later at the identity gate → "forbidden"). The old string compare against
	// "banned\n" could never match the JSON body, so it never actually tested this.
	var er struct {
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(rec2.Body.Bytes(), &er); err != nil {
		t.Fatal(err)
	}
	if er.Reason == "banned" {
		t.Fatal("an unbanned IP must not hit the ban gate")
	}
}

func waitCond(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition not reached in time")
}

// TestBanGatesRecordRejection: both phone-control ban gates are `ban` rejection writers (the
// writer map): the peer-IP gate with no tunnel, the tunnel gate with the name.
func TestBanGatesRecordRejection(t *testing.T) {
	m, _, _, _ := newMgr(t)
	var mu sync.Mutex
	var got [][2]string
	rej := func(reason, tunnel, _ string) {
		mu.Lock()
		got = append(got, [2]string{reason, tunnel})
		mu.Unlock()
	}
	banned := netip.MustParseAddr("198.51.100.97")
	h := NewHandler(HandlerConfig{DialBacks: NewDialBacks(tunneltest.Logger()), Manager: m, PingInterval: time.Hour, StreamPending: 4,
		BanIP:  func(a netip.Addr) bool { return a == banned },
		Reject: rej})

	req := httptest.NewRequest("GET", "/api/v1/control", nil)
	req.RemoteAddr = "198.51.100.97:40000"
	h.ServeHTTP(httptest.NewRecorder(), req)
	if len(got) != 1 || got[0] != [2]string{"ban", ""} {
		t.Fatalf("the IP ban gate must record Reject(ban, \"\"), got %v", got)
	}
}

func TestServeHTTP_TunnelNameBanGates(t *testing.T) {
	for _, path := range []string{"/api/v1/control", "/api/v1/issue"} {
		t.Run(path, func(t *testing.T) {
			m, _, _, _ := newMgr(t)
			var mu sync.Mutex
			var got [][3]string
			issued := 0
			h := NewHandler(HandlerConfig{DialBacks: NewDialBacks(tunneltest.Logger()), Manager: m, PingInterval: time.Hour, StreamPending: 4,
				BanTunnel: func(name string) bool { return name == "abcdef234567" },
				Reject: func(reason, tunnel, ip string) {
					mu.Lock()
					got = append(got, [3]string{reason, tunnel, ip})
					mu.Unlock()
				},
				OnIssue: func(context.Context, string, string, IssueRequest) (IssueResponse, *IssueError) {
					issued++
					return IssueResponse{}, nil
				}})
			req := tlsRequest(t, path, selfSignedCert(t, "abcdef234567", false))
			req.Method = http.MethodPost
			req.ProtoMajor, req.ProtoMinor = 2, 0
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			var body struct {
				Reason string `json:"reason"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if rec.Code != http.StatusForbidden || body.Reason != "banned" {
				t.Fatalf("a banned name on %s = %d %q, want 403 banned", path, rec.Code, body.Reason)
			}
			if len(got) != 1 || got[0] != [3]string{"ban", "abcdef234567", "198.51.100.50"} {
				t.Fatalf("the name ban must record Reject(ban, name, peer ip), got %v", got)
			}
			if names := m.ConnectedNames(); len(names) != 0 || issued != 0 {
				t.Fatalf("a banned name must neither bind (%v) nor issue (%d calls)", names, issued)
			}
		})
	}
}

func TestServeHTTP_ControlOverHTTP1Refused(t *testing.T) {
	h, m := newTestHandler(t, 4, time.Hour)
	body := newBlockedReader()
	defer body.close()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/control", body)
	req.RemoteAddr = "198.51.100.50:40000"
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{selfSignedCert(t, "abcdef234567", false)}}
	req.ProtoMajor, req.ProtoMinor = 1, 1
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusHTTPVersionNotSupported || rec.Header().Get("Connection") != "close" {
		t.Fatalf("HTTP/1.1 control = %d Connection=%q, want 505 + close", rec.Code, rec.Header().Get("Connection"))
	}
	if m.HasConn("abcdef234567") {
		t.Fatal("an HTTP/1.x control request must not bind")
	}
}

func TestServeHTTP_ControlHTTP1RefusalsArriveAtOnce(t *testing.T) {
	tests := []struct {
		name       string
		banned     bool
		wantReason string
	}{
		{name: "banned peer", banned: true, wantReason: "banned"},
		{name: "no client certificate", banned: false, wantReason: "forbidden"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, _, _, _ := newMgr(t)
			h := NewHandler(HandlerConfig{DialBacks: NewDialBacks(tunneltest.Logger()), Manager: m, PingInterval: time.Hour, StreamPending: 4,
				BanIP: func(netip.Addr) bool { return tc.banned }})
			srv := httptest.NewServer(h)
			defer srv.Close()
			pr, pw := io.Pipe()
			defer tunneltest.CloseLogged(pw)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/api/v1/control", pr)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatalf("the HTTP/1.1 refusal must arrive while the body stays open: %v", err)
			}
			defer tunneltest.CloseLogged(resp.Body)
			var body struct {
				Reason string `json:"reason"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusForbidden || body.Reason != tc.wantReason {
				t.Fatalf("answer = %d %q, want 403 %q", resp.StatusCode, body.Reason, tc.wantReason)
			}
		})
	}
}

func issuePost(t *testing.T, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/issue", strings.NewReader(body))
	req.RemoteAddr = "198.51.100.50:40000"
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{selfSignedCert(t, "abcdef234567", false)}}
	return req
}

func TestServeIssue_RetryableErrorIs503(t *testing.T) {
	m, _, _, _ := newMgr(t)
	h := NewHandler(HandlerConfig{DialBacks: NewDialBacks(tunneltest.Logger()), Manager: m, PingInterval: time.Hour, StreamPending: 4,
		OnIssue: func(context.Context, string, string, IssueRequest) (IssueResponse, *IssueError) {
			return IssueResponse{}, &IssueError{Reason: "identity_sign_failed", Retryable: true}
		}})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, issuePost(t, "{}"))
	var body struct {
		Reason    string `json:"reason"`
		Retryable bool   `json:"retryable"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusServiceUnavailable || body.Reason != "identity_sign_failed" || !body.Retryable {
		t.Fatalf("a retryable issue error = %d %+v, want 503 retryable identity_sign_failed", rec.Code, body)
	}
}

func TestServeIssue_HandlerDeadline(t *testing.T) {
	m, _, _, _ := newMgr(t)
	var deadline time.Time
	var hasDeadline bool
	h := NewHandler(HandlerConfig{DialBacks: NewDialBacks(tunneltest.Logger()), Manager: m, PingInterval: time.Hour, StreamPending: 4,
		OnIssue: func(ctx context.Context, _, _ string, _ IssueRequest) (IssueResponse, *IssueError) {
			deadline, hasDeadline = ctx.Deadline()
			return IssueResponse{}, nil
		}})
	before := time.Now()
	h.ServeHTTP(httptest.NewRecorder(), issuePost(t, "{}"))
	if !hasDeadline || deadline.Before(before.Add(390*time.Second)) || deadline.After(time.Now().Add(390*time.Second)) {
		t.Fatalf("OnIssue ctx deadline = %v (set %v), want 390 s after the request arrived", deadline, hasDeadline)
	}
}

func TestServeIssue_StalledBodyAnsweredAtDeadline(t *testing.T) {
	tests := []struct {
		name        string
		serverProto []string
		client      func(*tls.Config) *http.Transport
		wantMajor   int
	}{
		{name: "http/1.1", serverProto: []string{"http/1.1"}, wantMajor: 1, client: func(c *tls.Config) *http.Transport {
			return &http.Transport{TLSClientConfig: c, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}}
		}},
		{name: "h2", serverProto: []string{"h2", "http/1.1"}, wantMajor: 2, client: func(c *tls.Config) *http.Transport {
			return &http.Transport{TLSClientConfig: c, ForceAttemptHTTP2: true}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, _, _, _ := newMgr(t)
			testCA := newDBTestCA(t)
			var called atomic.Bool
			h := NewHandler(HandlerConfig{DialBacks: NewDialBacks(tunneltest.Logger()), Manager: m, PingInterval: time.Hour, StreamPending: 4,
				IssueDeadline: 200 * time.Millisecond,
				OnIssue: func(context.Context, string, string, IssueRequest) (IssueResponse, *IssueError) {
					called.Store(true)
					return IssueResponse{}, nil
				}})
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			srvTLS := &tls.Config{Certificates: []tls.Certificate{testCA.leaf(t, "connect.example.test", true, false)},
				ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: testCA.pool, MinVersion: tls.VersionTLS12, NextProtos: tc.serverProto}
			srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, TLSConfig: srvTLS}
			tunneltest.ServeHTTP(t, srv, tls.NewListener(ln, srvTLS))
			tr := tc.client(&tls.Config{ServerName: "connect.example.test", RootCAs: testCA.pool, MinVersion: tls.VersionTLS12,
				Certificates: []tls.Certificate{testCA.leaf(t, "abcdef234567", false, false)}})
			defer tr.CloseIdleConnections()
			pr, pw := io.Pipe()
			defer tunneltest.CloseLogged(pw)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+ln.Addr().String()+"/api/v1/issue", pr)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := (&http.Client{Transport: tr}).Do(req)
			if err != nil {
				t.Fatalf("a stalled /api/v1/issue upload must be answered at the deadline: %v", err)
			}
			defer tunneltest.CloseLogged(resp.Body)
			var body struct {
				Reason string `json:"reason"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if resp.ProtoMajor != tc.wantMajor || resp.StatusCode != http.StatusBadRequest || body.Reason != "bad_request" || called.Load() {
				t.Fatalf("stalled upload = HTTP/%d %d %q (OnIssue called %v), want HTTP/%d 400 bad_request without OnIssue",
					resp.ProtoMajor, resp.StatusCode, body.Reason, called.Load(), tc.wantMajor)
			}
		})
	}
}

// selfSignedCert builds a self-signed leaf with the given CN and optional mesh-role OU marker — the
// handler-level identity check inspects only the leaf (chain trust is the TLS layer's job).
func selfSignedCert(t *testing.T, cn string, meshRole bool) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	subj := pkix.Name{CommonName: cn}
	if meshRole {
		subj.OrganizationalUnit = []string{ca.MeshRoleOU}
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: subj,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func tlsRequest(t *testing.T, path string, leaf *x509.Certificate) *http.Request {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req.RemoteAddr = "198.51.100.50:40000"
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	return req
}

// TestServeHTTPRejectsMeshRoleCert covers the SACRED role separation on the phone listener: a
// mesh-role client cert MUST be refused even with a well-formed CN.
func TestServeHTTPRejectsMeshRoleCert(t *testing.T) {
	m, _, _, _ := newMgr(t)
	h := NewHandler(HandlerConfig{DialBacks: NewDialBacks(tunneltest.Logger()), Manager: m, PingInterval: time.Hour, StreamPending: 4,
		ValidName: func(string) bool { return true }})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tlsRequest(t, "/api/v1/control", selfSignedCert(t, "abcdef234567", true)))
	if rec.Code != 403 {
		t.Fatalf("a mesh-role cert must be refused on the phone listener, got %d", rec.Code)
	}
	if m.HasConn("abcdef234567") {
		t.Fatal("a mesh-role cert must never bind a phone connection")
	}
}

// TestControlData_NonPostIs405 covers the frozen wire contract (docs/PROTOCOL.md §3): /api/v1/control is
// POST; a GET that passes the cert + CN gates is refused 405.
func TestControlData_NonPostIs405(t *testing.T) {
	m, _, _, _ := newMgr(t)
	h := NewHandler(HandlerConfig{DialBacks: NewDialBacks(tunneltest.Logger()), Manager: m, PingInterval: time.Hour, StreamPending: 4,
		ValidName: func(string) bool { return true }})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tlsRequest(t, "/api/v1/control", selfSignedCert(t, "abcdef234567", false)))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /api/v1/control must be 405, got %d", rec.Code)
	}
}

// TestServeHTTPRejectsInvalidCN covers the CN gate: a malformed/reserved CN is refused before any
// route bind.
func TestServeHTTPRejectsInvalidCN(t *testing.T) {
	m, _, _, _ := newMgr(t)
	h := NewHandler(HandlerConfig{DialBacks: NewDialBacks(tunneltest.Logger()), Manager: m, PingInterval: time.Hour, StreamPending: 4,
		ValidName: func(name string) bool { return name == "goodname234567" }})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tlsRequest(t, "/api/v1/control", selfSignedCert(t, "Not A Valid Name!", false)))
	if rec.Code != 403 {
		t.Fatalf("a malformed CN must be refused, got %d", rec.Code)
	}
}

// TestHeartbeatMissingSelfHeals covers the three-state heartbeat's missing branch: a lapsed route is
// re-bound by the self-heal (this connection's route is restored under its own connID).
func TestHeartbeatMissingSelfHeals(t *testing.T) {
	m, fr, _, _ := newMgr(t)
	fr.hbResult = router.HeartbeatMissing
	c := newConn("selfheal01")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.cancel = cancel
	if _, err := m.register(ctx, c); err != nil {
		t.Fatal(err)
	}
	// Simulate the TTL lapse: drop the route, then let the heartbeat loop observe "missing".
	fr.mu.Lock()
	delete(fr.bound, "selfheal01")
	fr.mu.Unlock()

	m.routeTTL = 3 * time.Millisecond
	go m.heartbeatLoop(ctx, c)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got, ok := fr.boundConnID("selfheal01"); ok {
			if got != c.connID {
				t.Fatalf("self-heal must re-bind THIS conn's id: got %q want %q", got, c.connID)
			}
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("a missing route must be self-healed by the heartbeat loop")
}

// TestServeControl_BindFailureStatuses proves any (transient) bind failure answers 503 retryable.
func TestServeControl_BindFailureStatuses(t *testing.T) {
	tests := []struct {
		name     string
		bindErr  error
		wantCode int
	}{
		{name: "transient error → 503", bindErr: errors.New("valkey down"), wantCode: http.StatusServiceUnavailable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, fr, _, _ := newMgr(t)
			fr.bindErr = tc.bindErr
			h := NewHandler(HandlerConfig{DialBacks: NewDialBacks(tunneltest.Logger()), Manager: m, PingInterval: time.Hour, StreamPending: 4})
			rec := newFlushRecorder()
			req := httptest.NewRequest("GET", "/api/v1/control", newBlockedReader())
			h.serveControl(rec, req, phoneIdentity{name: "phonex"})
			if rec.code() != tc.wantCode {
				t.Fatalf("code = %d, want %d", rec.code(), tc.wantCode)
			}
			if m.HasConn("phonex") {
				t.Fatal("a failed bind must not register a connection")
			}
		})
	}
}

// TestServeControl_CertExpiryCloses proves a bound phone whose identity cert has passed NotAfter is
// closed cert-expired on the ping tick (the CA's exposure bound enforced live, not only at reconnect).
func TestServeControl_CertExpiryCloses(t *testing.T) {
	m, _, st, _ := newMgr(t)
	h := NewHandler(HandlerConfig{DialBacks: NewDialBacks(tunneltest.Logger()), Manager: m, PingInterval: 5 * time.Millisecond, StreamPending: 4})
	body := newBlockedReader()
	defer body.close()
	req := httptest.NewRequest("GET", "/api/v1/control", body)
	done := make(chan struct{})
	go func() {
		h.serveControl(newFlushRecorder(), req,
			phoneIdentity{name: "phoneexp", notAfter: time.Now().Add(-time.Minute)})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("an expired identity cert must close the conn on the ping tick")
	}
	var reason string
	for _, e := range st.ConnLogs {
		if e.Event == "end" {
			reason = e.CloseReason
		}
	}
	if reason != store.CloseCertExpired {
		t.Fatalf("end close_reason = %q, want %q", reason, store.CloseCertExpired)
	}
}

func TestServeHTTP_UnparseablePeerRefused(t *testing.T) {
	m, _, _, _ := newMgr(t)
	h := NewHandler(HandlerConfig{DialBacks: NewDialBacks(tunneltest.Logger()), Manager: m, PingInterval: time.Hour, StreamPending: 4,
		BanIP: func(netip.Addr) bool {
			t.Error("the ban gate must not be consulted for an unparseable peer")
			return false
		}})
	req := httptest.NewRequest("GET", "/api/v1/control", nil)
	req.RemoteAddr = "@peer"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var er struct {
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &er); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusBadRequest || er.Reason != "bad_source_ip" {
		t.Fatalf("unparseable peer = %d %q, want 400 bad_source_ip", rec.Code, er.Reason)
	}
}

func TestServeControl_BindFailureLogging(t *testing.T) {
	tests := []struct {
		name      string
		bindErr   error
		cancelled bool
		wantLog   bool
	}{
		{name: "transient failure is logged", bindErr: errors.New("valkey down"), wantLog: true},
		{name: "cancelled request is silent", bindErr: context.Canceled, cancelled: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fr := newFakeRouter()
			fr.bindErr = tc.bindErr
			var buf bytes.Buffer
			m := NewManager(Config{Router: fr, Logs: tunneltest.NewStore(), Recorder: &fakeRec{}, Closed: nopClosedHook{},
				NodeID: "nodeA", NodeHost: "host-a", NodeStart: "2026-08-18T00:00:00Z",
				RouteTTL: 30 * time.Second, Logger: slog.New(slog.NewTextHandler(&buf, nil))})
			h := NewHandler(HandlerConfig{DialBacks: NewDialBacks(tunneltest.Logger()), Manager: m, PingInterval: time.Hour, StreamPending: 4})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancelled {
				cancel()
			}
			req := httptest.NewRequest("GET", "/api/v1/control", newBlockedReader()).WithContext(ctx)
			rec := newFlushRecorder()
			h.serveControl(rec, req, phoneIdentity{name: "phonex"})
			if rec.code() != http.StatusServiceUnavailable {
				t.Fatalf("code = %d, want 503", rec.code())
			}
			if logged := strings.Contains(buf.String(), `msg="phone route bind failed"`); logged != tc.wantLog {
				t.Fatalf("logged = %v, want %v; log = %q", logged, tc.wantLog, buf.String())
			}
		})
	}
}
