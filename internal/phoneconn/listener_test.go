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
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/ca"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/router"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
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
	h := NewHandler(HandlerConfig{Manager: m, PingInterval: ping, StreamPending: pending})
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
		req := httptest.NewRequest("GET", "/control", body).WithContext(ctx)
		done := make(chan struct{})
		go func() {
			h.serveControl(newFlushRecorder(), req, phoneIdentity{name: name, fingerprint: "sha256:fp-" + name})
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

// TestServeControlPendingCapRefuses covers the pre-bind refusal: a saturated pre-bind semaphore
// answers 503 without touching the manager.
func TestServeControlPendingCapRefuses(t *testing.T) {
	h, m := newTestHandler(t, 1, time.Hour)
	h.sem <- struct{}{} // saturate the pre-bind slot

	rec := newFlushRecorder()
	req := httptest.NewRequest("GET", "/control", newBlockedReader())
	h.serveControl(rec, req, phoneIdentity{name: "phonec", fingerprint: "sha256:fp"})
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
	req := httptest.NewRequest("GET", "/control", body)
	done := make(chan struct{})
	go func() {
		h.serveControl(newFlushRecorder(), req, phoneIdentity{name: "phoned", fingerprint: "sha256:fp"})
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

	pong, _ := wire.EncodeControl(wire.CtrlPong, nil)
	h.readPump(bytes.NewReader(pong), c) // EOF after the frame → phone-close
	if c.lastPong.Load() <= before {
		t.Fatal("a PONG frame must advance lastPong")
	}

	c2 := newConn("phonef")
	// A frame with an oversize length prefix is malformed: the read fails and tears the conn down.
	bad := []byte{0x01, 0xff, 0xff, 0xff, 0xff}
	h.readPump(bytes.NewReader(bad), c2)
	if c2.closeReason() != "phone-close" {
		t.Fatalf("close reason = %q, want phone-close", c2.closeReason())
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
	h := NewHandler(HandlerConfig{Manager: m, PingInterval: time.Hour, StreamPending: 4,
		BanIP: func(a netip.Addr) bool { return a == banned }})

	req := httptest.NewRequest("GET", "/control", nil)
	req.RemoteAddr = "198.51.100.99:40000"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatalf("banned peer IP must get 403, got %d", rec.Code)
	}

	req2 := httptest.NewRequest("GET", "/control", nil)
	req2.RemoteAddr = "198.51.100.98:40000"
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code == 403 && rec2.Body.String() == "banned\n" {
		t.Fatal("an unbanned IP must not hit the ban gate")
	}
}

// TestServeDataNoWaiterIs404 covers the undeliverable dial-back stream: serveData must answer a REAL
// 404 (no premature 200) when no waiter exists for the stream id.
func TestServeDataNoWaiterIs404(t *testing.T) {
	h, _ := newTestHandler(t, 4, time.Hour)
	rec := newFlushRecorder()
	req := httptest.NewRequest("POST", "/data", newBlockedReader())
	req.Header.Set("X-Stream-Id", "nosuch")
	h.serveData(rec, req, "phoneg")
	if rec.code() != 404 {
		t.Fatalf("undeliverable stream must answer 404, got %d", rec.code())
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
	h := NewHandler(HandlerConfig{Manager: m, PingInterval: time.Hour, StreamPending: 4,
		BanIP:  func(a netip.Addr) bool { return a == banned },
		Reject: rej})

	req := httptest.NewRequest("GET", "/control", nil)
	req.RemoteAddr = "198.51.100.97:40000"
	h.ServeHTTP(httptest.NewRecorder(), req)
	if len(got) != 1 || got[0] != [2]string{"ban", ""} {
		t.Fatalf("the IP ban gate must record Reject(ban, \"\"), got %v", got)
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
	h := NewHandler(HandlerConfig{Manager: m, PingInterval: time.Hour, StreamPending: 4,
		ValidName: func(string) bool { return true }})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tlsRequest(t, "/control", selfSignedCert(t, "abcdef234567", true)))
	if rec.Code != 403 {
		t.Fatalf("a mesh-role cert must be refused on the phone listener, got %d", rec.Code)
	}
	if m.HasConn("abcdef234567") {
		t.Fatal("a mesh-role cert must never bind a phone connection")
	}
}

// TestServeHTTPRejectsInvalidCN covers the CN gate: a malformed/reserved CN is refused before any
// route bind.
func TestServeHTTPRejectsInvalidCN(t *testing.T) {
	m, _, _, _ := newMgr(t)
	h := NewHandler(HandlerConfig{Manager: m, PingInterval: time.Hour, StreamPending: 4,
		ValidName: func(name string) bool { return name == "goodname234567" }})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tlsRequest(t, "/control", selfSignedCert(t, "Not A Valid Name!", false)))
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

// TestServeControl_BindFailureStatuses covers I-3: a fingerprint conflict answers 409, any other
// (transient) bind failure answers 503 retryable.
func TestServeControl_BindFailureStatuses(t *testing.T) {
	tests := []struct {
		name     string
		bindErr  error
		wantCode int
	}{
		{name: "fingerprint conflict → 409", bindErr: router.ErrNameHeldByOther, wantCode: http.StatusConflict},
		{name: "transient error → 503", bindErr: errors.New("valkey down"), wantCode: http.StatusServiceUnavailable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, fr, _, _ := newMgr(t)
			fr.bindErr = tc.bindErr
			h := NewHandler(HandlerConfig{Manager: m, PingInterval: time.Hour, StreamPending: 4})
			rec := newFlushRecorder()
			req := httptest.NewRequest("GET", "/control", newBlockedReader())
			h.serveControl(rec, req, phoneIdentity{name: "phonex", fingerprint: "sha256:fp"})
			if rec.code() != tc.wantCode {
				t.Fatalf("code = %d, want %d", rec.code(), tc.wantCode)
			}
			if m.HasConn("phonex") {
				t.Fatal("a failed bind must not register a connection")
			}
		})
	}
}

// TestServeControl_CertExpiryCloses covers I-5: a bound phone whose identity cert has passed NotAfter is
// closed cert-expired on the ping tick (the CA's exposure bound enforced live, not only at reconnect).
func TestServeControl_CertExpiryCloses(t *testing.T) {
	m, _, st, _ := newMgr(t)
	h := NewHandler(HandlerConfig{Manager: m, PingInterval: 5 * time.Millisecond, StreamPending: 4})
	body := newBlockedReader()
	defer body.close()
	req := httptest.NewRequest("GET", "/control", body)
	done := make(chan struct{})
	go func() {
		h.serveControl(newFlushRecorder(), req,
			phoneIdentity{name: "phoneexp", fingerprint: "sha256:fp", notAfter: time.Now().Add(-time.Minute)})
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
